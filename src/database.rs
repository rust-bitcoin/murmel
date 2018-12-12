//
// Copyright 2018 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//!
//! # Database layer for the Bitcoin SPV client
//!
//! Stores the blockchain (mostly header), the wallet and various runtime and configuration data.
//!


use bitcoin::blockdata::block::{BlockHeader, Block};
use bitcoin::network::constants::Network;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::network::address::Address;
use bitcoin::util::hash::{BitcoinHash, Sha256dHash};
use blockfilter::UTXOAccessor;
use error::SPVError;

use hammersbald::api::HammersbaldAPI;
use hammersbald::api::HammersbaldFactory;
use hammersbald::persistent::Persistent;
use hammersbald::transient::Transient;

use headerstore::{HeaderStore, StoredHeader};
use filterstore::FilterStore;

use rusqlite;
use rusqlite::Connection;
use rusqlite::Error;
use rusqlite::OpenFlags;
use rusqlite::Statement;
use std::io::Cursor;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::sync::RwLock;
use std::cell::Cell;

use rand;
use rand::RngCore;

/// Database interface to connect
/// start, commit or rollback transactions
/// # Example
/// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct DB {
    conn: Connection,
    headers: RwLock<HeaderStore>,
    blocks: RwLock<FilterStore>
}

/// All database operations are accessible through this transaction wrapper, that also
/// supports Transaction commit and Rollback
/// /// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct DBTX<'a> {
    tx: rusqlite::Transaction<'a>,
    headers: &'a RwLock<HeaderStore>,
    blocks: &'a RwLock<FilterStore>,
    dirty: Cell<bool>
}

impl DB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<DB, SPVError> {
        info!("working with memory database");
        let mut headers = Transient::new_db("h", 1, 2)?;
        headers.init()?;
        let mut blocks = Transient::new_db("b", 1, 2)?;
        blocks.init()?;
        Ok(DB { conn: Connection::open_in_memory()?, headers: RwLock::new(HeaderStore::new(headers, network)),
            blocks: RwLock::new(FilterStore::new(blocks))})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<DB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let mut headers = Persistent::new_db((basename.clone() + ".h").as_str(), 100, 2)?;
        headers.init()?;
        let mut blocks = Persistent::new_db((basename + ".b").as_str(), 100, 2)?;
        blocks.init()?;
        let db = DB {
            conn: Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX)?,
            headers: RwLock::new(HeaderStore::new(headers, network)),
            blocks: RwLock::new(FilterStore::new(blocks))
        };
        info!("database {:?} opened", path);
        Ok(db)
    }

    /// Start a transaction. All operations must happen within the context of a transaction
    pub fn transaction<'a>(&'a mut self) -> Result<DBTX<'a>, SPVError> {
        trace!("starting transaction");
        Ok(DBTX { tx: self.conn.transaction()?, headers: &self.headers, blocks: &self.blocks, dirty: Cell::new(false) })
    }
}

impl<'a> DBTX<'a> {
    /// commit the transaction
    pub fn commit(self) -> Result<(), SPVError> {
        self.batch()?;
        if self.dirty.get() {
            self.tx.commit()?;
            trace!("committed transaction");
        }
        Ok(())
    }

    /// rollback the transaction
    pub fn rollback(self) -> Result<(), SPVError> {
        self.tx.rollback()?;
        trace!("rolled back transaction");
        Ok(())
    }

    /// batch hammersbald writes
    pub fn batch (&self) -> Result<(), SPVError> {
        self.blocks.write().unwrap().batch()?;
        Ok(self.headers.write().unwrap().batch()?)
    }

    /// Create tables suitable for blockchain storage
    /// Tables:
    ///   * ids - maps hashes to integers for better performance, all othe rtables use integers mapped here for hashes
    ///   * tip - hold the highest hash on trunk (the chain with the most work)
    ///   * header - block header
    ///   * tx - transactions
    ///   * blk_tx - n:m mapping of header to transactions to form a block.
    ///   * peers - list of known peers
    pub fn create_tables(&self) -> Result<u32, SPVError> {
        trace!("creating tables...");
        self.dirty.set(true);

        self.tx.execute("create table if not exists peers (
                                address text primary key,
                                port integer,
                                services integer,
                                last_seen integer,
                                banned_until integer)", &[])?;


        self.tx.execute("create table if not exists birth (inception integer)", &[])?;

        let stored_birth = self.get_birth ();
        if stored_birth.is_err() {
            let birth = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;

            self.tx.execute("insert into birth (inception) values (?)", &[&birth])?;
        }
        trace!("created tables");
        self.get_birth()
    }


    /// get the integer proxy for a hash. All tables use integers mapped here for better performance.
    pub fn get_birth(&self) -> Result<u32, SPVError> {
        Ok(self.tx.query_row("select inception from birth",
                             &[],
                             |row| {
                                 row.get(0)
                             })?)
    }

    /// store a peer
    ///   * last_seen - in unix epoch seconds
    ///   * banned_until - in unix epoch seconds
    ///   * speed - in ms as measured with ping
    pub fn store_peer (&self, address: &Address, last_seen: u32, banned_until: u32) -> Result<(), SPVError> {
        self.dirty.set(true);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }

        let row: Result<i64, Error> = self.tx.query_row(
            "select rowid from peers where address = ?", &[&s], | row | { row.get(0) });
        if let Ok (r) = row {
            self.tx.execute("update peers set last_seen = ? where rowid = ?", &[&last_seen, &r])?;
        }
        else {
            self.tx.execute("insert into peers (address, port, services, last_seen, banned_until) \
                        values (?, ?, ?, ?, ?)", &[&s, &address.port, &(address.services as i64), &last_seen, &banned_until])?;
        }
        Ok(())
    }

    pub fn ban (&self, addr: &SocketAddr) -> Result<i32, SPVError> {
        self.dirty.set(true);
        let address = Address::new (addr, 0);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }
        let banned_until = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 + 2*24*60;
        Ok(self.tx.execute("update peers set banned_until = ? where address = ?", &[&banned_until, &s])?)
    }

    pub fn remove_peer (&self, addr: &SocketAddr) -> Result<i32, SPVError> {
        self.dirty.set(true);
        let address = Address::new (addr, 0);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }
        Ok(self.tx.execute("delete from peers where address = ?", &[&s])?)
    }

    /// get a random stored peer
    pub fn get_a_peer (&self, earlier: &HashSet<SocketAddr>) -> Result<Address, SPVError> {
        let n_peers: i64 = self.tx.query_row(
            "select count(*) from peers", &[], | row | { row.get(0) })?;

        if n_peers == 0 {
            return Err(SPVError::Generic("no peers in the database".to_owned()));
        }

        let mut rng = rand::thread_rng();
        for _ in 0 .. 100 { // give up after 100 attempts
            let rowid = (rng.next_u64() as i64) % n_peers + 1;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
            let address:Result<(String, u16, i64), Error> = self.tx.query_row(
                "select address, port, services from peers where rowid = ? and banned_until < ? ", &[&(rowid as i64), &now], |row| {
                    (row.get(0), row.get(1), row.get(2) ) });
            if let Ok(a) = address {
                let mut tail = a.0.as_str();
                let mut v = [0u16; 8];
                for i in 0..8 {
                    let (digit, mut t) = tail.split_at(4);
                    tail = t;
                    v [i] = u16::from_str_radix(digit, 16).unwrap_or(0);
                }
                let peer = Address {
                    address: v,
                    port: a.1,
                    services: a.2 as u64
                };
                if let Ok(addr) = peer.socket_addr() {
                    if !earlier.contains(&addr) {
                        return Ok(peer)
                    }
                }
            }
        }
        Err(SPVError::Generic("no useful peers in the database".to_owned()))
    }

    /// Get the hash of the highest hash on the chain with most work
    pub fn get_tip(&self) -> Result<Option<Sha256dHash>, SPVError> {
        let hb = self.headers.read().unwrap();
        if let Some(tip) = hb.tip()? {
            return Ok(Some(tip.header.bitcoin_hash()))
        }
        Ok(None)
    }

    /// Store a header into the DB. This method will return an error if the header is already stored.
    pub fn insert_header(&self, header: &BlockHeader) -> Result<(), SPVError> {
        let mut hb = self.headers.write().unwrap();
        hb.insert_header(header)?;
        Ok(())
    }

    /// Store a transaction
    pub fn store_block (&self, block: &Block) -> Result<(), SPVError> {
        let mut hb = self.blocks.write().unwrap();
        hb.insert_block(block, vec!())?;
        Ok(())
    }

    /// Get a stored header. This method will return an error for an unknown header.
    pub fn get_header(&self, hash: &Sha256dHash) -> Result<Option<StoredHeader>, SPVError> {
        let hb = self.headers.read().unwrap();
        hb.fetch_header(hash)
    }

    /// get locator
    pub fn locator_hashes(&self) -> Result<Vec<Sha256dHash>, SPVError> {
        let mut locator = vec!();
        let hb = self.headers.read().unwrap();
        let mut skip = 1;
        if let Some(mut h) = hb.tip()? {
            locator.push(h.header.bitcoin_hash());
            while h.header.prev_blockhash != Sha256dHash::default() {
                if let Some(prev) = hb.fetch_header(&h.header.prev_blockhash)? {
                    h = prev;
                }
                else {
                    return Err(SPVError::Generic("tip is not connected to genesis".to_string()));
                }
                locator.push(h.header.bitcoin_hash());
                if locator.len() > 10 {
                    skip *= 2;
                }
                for _ in 1..skip {
                    if h.header.prev_blockhash == Sha256dHash::default() {
                        break;
                    }
                    if let Some(prev) = hb.fetch_header(&h.header.prev_blockhash)? {
                        h = prev;
                    }
                    else {
                        return Err(SPVError::Generic("tip is not connected to genesis".to_string()));
                    }
                }
            }
        }
        Ok(locator)
    }

    pub fn insert_filter (&self, _block_hash: &Sha256dHash, _prev_block_hash: &Sha256dHash, _filter_type: u8, _content: &Vec<u8>) -> Result<Sha256dHash, SPVError> {
        unimplemented!()
    }

    /// read headers and filters into an in-memory tree, return the number of headers on trunk
    pub fn init_node(&self, network: Network) -> Result<(), SPVError> {
        if self.get_tip()?.is_none() {
            use bitcoin::blockdata::constants::genesis_block;

            self.insert_header(&genesis_block(network).header)?;
        }
        let mut hb = self.headers.write().unwrap();
        hb.init_cache()?;
        Ok(())
    }

    /// check if hash is on trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        let hb = self.headers.read().unwrap();
        hb.is_on_trunk(hash)
    }
}

fn decode<'d, T: ? Sized>(data: Vec<u8>) -> Result<T, SPVError>
    where T: Decodable<Cursor<Vec<u8>>> {
    let mut decoder  = Cursor::new(data);
    Decodable::consensus_decode(&mut decoder).map_err(|e| { SPVError::Serialize(e) })
}

fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, SPVError>
    where T: Encodable<Vec<u8>> {
    let mut result = vec!();
    data.consensus_encode(&mut result).map_err(|e| { SPVError::Serialize(e) })?;
    Ok(result)
}

fn encode_id(data: &Sha256dHash) -> Result<Vec<u8>, SPVError> {
    Ok(data.be_hex_string().as_bytes().to_vec())
}

fn decode_id(data: Vec<u8>) -> Result<Sha256dHash, SPVError> {
    use std::str::from_utf8;
    if let Ok(s) = from_utf8(data.as_slice()) {
        if let Ok (hash) = Sha256dHash::from_hex(s) {
            return Ok(hash);
        }
    }
    return Err(SPVError::Generic("unable to decode id to a hash".to_owned()));
}

pub struct DBUTXOAccessor<'a> {
    tx: &'a DBTX<'a>,
    same_block_utxo: HashMap<(Sha256dHash, u32), (Script, u64)>,
    query: Statement<'a>
}

impl<'a> DBUTXOAccessor<'a> {
    pub fn new(tx: &'a DBTX<'a>, block: &Block) -> Result<DBUTXOAccessor<'a>, SPVError> {
        let query = tx.tx.prepare("select content from tx where id = ?")?;
        let mut acc = DBUTXOAccessor { tx, same_block_utxo: HashMap::new(), query };
        for t in &block.txdata {
            let id = t.txid();
            for (ix, o) in t.output.iter().enumerate() {
                acc.same_block_utxo.insert((id, ix as u32), (o.script_pubkey.clone(), o.value));
            }
        }
        Ok(acc)
    }
}

impl<'a> UTXOAccessor for DBUTXOAccessor<'a> {
    fn get_utxo(&mut self, txid: &Sha256dHash, ix: u32) -> Result<(Script, u64), io::Error> {
        if let Some(utxo) = self.same_block_utxo.get(&(*txid, ix)) {
            return Ok(utxo.clone());
        }
        if let Ok(content) = self.query.query_row(&[&encode_id(txid)?], |row| row.get(0)) {
            let tx: Transaction = decode(content)?;
            if let Some(output) = tx.output.get(ix as usize) {
                return Ok((output.script_pubkey.clone(), output.value))
            }
        }
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }
}

#[cfg(test)]
mod test {
    use bitcoin::blockdata::constants;
    use bitcoin::network;
    use bitcoin::network::constants::Network;
    use bitcoin::util::hash::{BitcoinHash};
    use super::DB;

    #[test]
    fn test_db1() {
        let mut db = DB::mem(Network::Bitcoin).unwrap();
        let tx = db.transaction().unwrap();
        tx.create_tables().unwrap();
        let genesis = constants::genesis_block(network::constants::Network::Bitcoin);
        tx.insert_header(&genesis.header).unwrap();
        let header = tx.get_header(&genesis.header.bitcoin_hash()).unwrap().unwrap();
        assert_eq!(header.header.bitcoin_hash(), genesis.bitcoin_hash());
        assert_eq!(Some(genesis.header.bitcoin_hash()), tx.get_tip().unwrap());
        tx.commit().unwrap();
    }
}
