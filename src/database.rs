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
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use bitcoin::network::serialize::{RawDecoder, RawEncoder};
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::network::serialize::serialize;
use bitcoin::network::address::Address;
use bitcoin::util::hash::Sha256dHash;
use bitcoin_chain::blockchain::Blockchain;
use blockfilter::{BlockFilter,UTXOAccessor};
use error::SPVError;

use hammersbald::bitcoin_support::BitcoinAdapter;
use hammersbald::api::HammersbaldAPI;
use hammersbald::api::HammersbaldFactory;
use hammersbald::persistent::Persistent;
use hammersbald::transient::Transient;

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
use rand::Rng;
use rand::RngCore;

// maximum number of blocks UTXO can unwind
const UNWIND_LIMIT :i64 = 100;

/// Database interface to connect
/// start, commit or rollback transactions
/// # Example
/// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct DB {
    conn: Connection,
    hammersbald: RwLock<BitcoinAdapter>
}

/// All database operations are accessible through this transaction wrapper, that also
/// supports Transaction commit and Rollback
/// /// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct DBTX<'a> {
    tx: rusqlite::Transaction<'a>,
    hammersbald: &'a RwLock<BitcoinAdapter>,
    dirty: Cell<bool>
}

impl DB {
    /// Create an in-memory database instance
    pub fn mem() -> Result<DB, SPVError> {
        info!("working with memory database");
        let mut hammersbald = Transient::new_db("", 1)?;
        hammersbald.init()?;
        Ok(DB { conn: Connection::open_in_memory()?, hammersbald: RwLock::new(BitcoinAdapter::new(hammersbald)) })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path) -> Result<DB, SPVError> {
        let mut hammersbald = Persistent::new_db(path.to_str().unwrap(), 100)?;
        hammersbald.init()?;
        let db = DB {
            conn: Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX)?,
            hammersbald: RwLock::new(BitcoinAdapter::new(hammersbald))
        };
        info!("database {:?} opened", path);
        Ok(db)
    }

    /// Start a transaction. All operations must happen within the context of a transaction
    pub fn transaction<'a>(&'a mut self) -> Result<DBTX<'a>, SPVError> {
        trace!("starting transaction");
        Ok(DBTX { tx: self.conn.transaction()?, hammersbald: &self.hammersbald, dirty: Cell::new(false) })
    }
}

impl<'a> DBTX<'a> {
    /// commit the transaction
    pub fn commit(self) -> Result<(), SPVError> {
        self.hammersbald.write().unwrap().batch()?;
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
    pub fn batch (self) -> Result<(), SPVError> {
        Ok(self.hammersbald.write().unwrap().batch()?)
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

    /// Set the highest hash for the chain with most work
    pub fn set_tip(&self, tip: &Sha256dHash) -> Result<(), SPVError> {
        trace!("storing tip {}", tip);
        let mut hb = self.hammersbald.write().unwrap();
        hb.put(Sha256dHash::default().as_bytes(), tip.as_bytes(), &vec!())?;
        Ok(())
    }

    /// Get the hash of the highest hash on the chain with most work
    pub fn get_tip(&self) -> Result<Option<Sha256dHash>, SPVError> {
        let hb = self.hammersbald.read().unwrap();
        if let Some((_, tip, _)) = hb.get(Sha256dHash::default().as_bytes())? {
            return Ok(Some(decode(tip)?));
        }
        return Ok(None)
    }

    /// Store a header into the DB. This method will return an error if the header is already stored.
    pub fn insert_header(&self, header: &BlockHeader) -> Result<(), SPVError> {
        let mut hb = self.hammersbald.write().unwrap();
        hb.insert_header(header, &Vec::new())?;
        hb.fetch_header(&header.bitcoin_hash())?;
        Ok(())
    }

    /// Store a transaction
    pub fn store_block (&self, block: &Block) -> Result<(), SPVError> {
        let mut hb = self.hammersbald.write().unwrap();
        hb.insert_block(block, &Vec::new())?;
        Ok(())
    }

    /// Get a stored header. This method will return an error for an unknown header.
    pub fn get_header(&self, hash: &Sha256dHash) -> Result<Option<BlockHeader>, SPVError> {
        let hb = self.hammersbald.read().unwrap();
        if let Some((header, ext)) = hb.fetch_header(hash)? {
            Ok(Some(header))
        }
        else {
            Ok(None)
        }
    }

    pub fn insert_filter (&self, block_hash: &Sha256dHash, prev_block_hash: &Sha256dHash, filter_type: u8, content: &Vec<u8>) -> Result<Sha256dHash, SPVError> {
        unimplemented!()
    }

    /// read headers and filters into an in-memory tree, return the number of headers on trunk
    pub fn init_node(&self, blockchain: &mut Blockchain, filters: &mut HashMap<Sha256dHash, (Sha256dHash, u8, Vec<u8>)>) -> Result<u32, SPVError> {
        let mut trunk = Vec::new();
        if let Ok(Some(mut current)) = self.get_tip() {
            trunk.push(current);
            let bcdb = self.hammersbald.read().unwrap();
            while current != blockchain.genesis_hash() {
                if let Some((header, _)) = bcdb.fetch_header(&current)? {
                    trunk.push(header.prev_blockhash);
                    current = header.prev_blockhash;
                }
                else {
                    return Err(SPVError::Generic("broken chain".to_string()));
                }
            }
            let mut reverse = trunk.iter().rev();
            reverse.next(); // skip genesis
            for hash in reverse {
                if let Some((header, _)) = bcdb.fetch_header(&hash)? {
                    blockchain.add_header(header)?;
                }
            }
            return Ok(trunk.len() as u32 - 1);
        }
        Ok(0)
    }
}

fn decode<T: ? Sized>(data: Vec<u8>) -> Result<T, SPVError>
    where T: ConsensusDecodable<RawDecoder<Cursor<Vec<u8>>>> {
    let mut decoder: RawDecoder<Cursor<Vec<u8>>> = RawDecoder::new(Cursor::new(data));
    ConsensusDecodable::consensus_decode(&mut decoder).map_err(|e| { SPVError::Serialize(e) })
}

fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, SPVError>
    where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>> {
    serialize(data).map_err(|e| { SPVError::Serialize(e) })
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
    use bitcoin::network::serialize::BitcoinHash;
    use bitcoin::util::hash::Sha256dHash;
    use super::DB;

    #[test]
    fn test_db1() {
        let mut db = DB::mem().unwrap();
        let tx = db.transaction().unwrap();
        tx.create_tables().unwrap();
        tx.set_tip(&Sha256dHash::default()).unwrap();
        assert_eq!(Some(Sha256dHash::default()), tx.get_tip().unwrap());
        let genesis = constants::genesis_block(network::constants::Network::Bitcoin);
        tx.insert_header(&genesis.header).unwrap();
        let header = tx.get_header(&genesis.header.bitcoin_hash()).unwrap().unwrap();
        assert_eq!(header.bitcoin_hash(), genesis.bitcoin_hash());
        tx.set_tip(&genesis.header.bitcoin_hash()).unwrap();

        assert_eq!(Some(genesis.header.bitcoin_hash()), tx.get_tip().unwrap());
        tx.commit().unwrap();
    }
}
