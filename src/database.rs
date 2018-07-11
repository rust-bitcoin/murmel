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
use rand;
use rand::Rng;

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
    conn: Connection
}

/// All database operations are accessible through this transaction wrapper, that also
/// supports Transaction commit and Rollback
/// /// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct DBTX<'a> {
    tx: rusqlite::Transaction<'a>
}

impl DB {
    /// Create an in-memory database instance
    pub fn mem() -> Result<DB, SPVError> {
        info!("working with memory database");
        Ok(DB { conn: Connection::open_in_memory()? })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path) -> Result<DB, SPVError> {
        let db = DB {
            conn: Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX)?
        };
        info!("database {:?} opened", path);
        Ok(db)
    }

    /// Start a transaction. All operations must happen within the context of a transaction
    pub fn transaction<'a>(&'a mut self) -> Result<DBTX<'a>, SPVError> {
        trace!("starting transaction");
        Ok(DBTX { tx: self.conn.transaction()? })
    }
}

impl<'a> DBTX<'a> {
    /// commit the transaction
    pub fn commit(self) -> Result<(), SPVError> {
        self.tx.commit()?;
        trace!("committed transaction");
        Ok(())
    }

    /// rollback the transaction
    pub fn rollback(self) -> Result<(), SPVError> {
        self.tx.commit()?;
        trace!("rolled back transaction");
        Ok(())
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

        self.tx.execute("create table if not exists tip (
                                headers text
                                )", &[])?;

        self.tx.execute("create table if not exists header (
                                id text primary key,
                                prev text,
                                data blob,
                                txids blob
                                )", &[])?;

        self.tx.execute("create table if not exists tx (
                                id text primary key,
                                content blob
                                )", &[])?;

        self.tx.execute("create table if not exists peers (
                                address text primary key,
                                port integer,
                                services integer,
                                last_seen integer,
                                banned_until integer)", &[])?;

        self.tx.execute("create table if not exists filters (
                                block text,
                                filter_type integer,
                                filter_id text,
                                content blob,
                                primary key(block, filter_type)
                                )", &[])?;

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
        let address = Address::new (addr, 0);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }
        let banned_until = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 + 2*24*60;
        Ok(self.tx.execute("update peers set banned_until = ? where address = ?", &[&banned_until, &s])?)
    }

    pub fn remove_peer (&self, addr: &SocketAddr) -> Result<i32, SPVError> {
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
    pub fn set_tip(&self, headers: &Sha256dHash) -> Result<(), SPVError> {
        trace!("storing tip {}", headers);
        self.tx.execute("delete from tip", &[]).map(|_| { () })?;
        Ok(self.tx.execute("insert into tip (headers) values (?)", &[&encode_id(headers)?]).map(|_| { () })?)
    }

    /// Get the hash of the highest hash on the chain with most work
    pub fn get_tip(&self) -> Result<Sha256dHash, SPVError> {
        decode_id(self.tx.query_row("select headers from tip",
                                        &[], |row| { row.get(0) })?)
    }

    /// Store a header into the DB. This method will return an error if the header is already stored.
    pub fn insert_header(&self, header: &BlockHeader) -> Result<(), SPVError> {
        let hash = header.bitcoin_hash();
        self.tx.execute("insert into header (id, prev, data) values (?, ?, ?)",
                        &[&encode_id(&hash)?, &encode_id(&header.prev_blockhash)?, &encode(header)?])?;
        Ok(())
    }

    /// Store a transaction
    pub fn store_block (&self, block: &Block) -> Result<(), SPVError> {
        let block_hash = &encode_id(&block.bitcoin_hash())?;
        let mut update_header = self.tx.prepare("update header set txids = ? where id = ?")?;
        let mut check_tx = self.tx.prepare("select id from tx where id = ?")?;
        let mut insert_tx = self.tx.prepare("insert into tx (id, content) values (?,?)")?;

        let mut txs = Vec::new();
        for tx in &block.txdata {
            let txid = tx.txid();
            txs.push(txid);
            let tx_hash = &encode_id(&txid)?;
            if check_tx.query_row(&[tx_hash], |_| true).is_err() {
                insert_tx.execute(&[tx_hash, &encode(tx)?])?;
            }
        }
        update_header.execute(&[&encode(&txs)?, block_hash])?;
        Ok(())
    }

    /// Get a stored header. This method will return an error for an unknown header.
    pub fn get_header(&self, hash: &Sha256dHash) -> Result<BlockHeader, SPVError> {
        decode(self.tx.query_row("select data from header where id = ?",
                                 &[&encode_id(hash)?], |row| { row.get(0) })?)
    }

    /*
    "create table if not exists filters (
                                block blob(32),
                                filter_type integer,
                                filter_id blob(32),
                                content blob,
                                primary key(block, filter_type)
                                )"
    */

    pub fn insert_filter (&self, block_hash: &Sha256dHash, prev_block_hash: &Sha256dHash, filter_type: u8, content: &Vec<u8>) -> Result<Sha256dHash, SPVError> {
        let filter_id = Sha256dHash::default();
        let prev_filter_id;
        if let Ok(row) = self.tx.query_row("select filter_id from filters where block = ? and filter_type = ?",
                                                            &[&encode_id(prev_block_hash)?, &filter_type], | row | { row.get(0) }) {
            prev_filter_id = decode_id(row)?;
        }
        else {
            if *prev_block_hash == Sha256dHash::default() {
                prev_filter_id = Sha256dHash::default();
            }
            else {
                return Err(SPVError::Generic(format!("can not find previous filter for block {}", prev_block_hash)));
            }
        }

        let filter_hash = Sha256dHash::from_data(content.as_slice());
        let mut header_data = [0u8; 64];
        header_data[0..32].copy_from_slice(&filter_hash.data()[0..32]);
        header_data[32..64].copy_from_slice(&prev_filter_id.data()[0..32]);
        let filter_id = Sha256dHash::from_data(&header_data);

        self.tx.execute("insert into filters (block, filter_type, filter_id, content) values (?,?,?,?)",
                        &[&encode_id(block_hash)?, &filter_type, &encode_id(&filter_id)?, content])?;
        Ok(filter_id)
    }

    /// read headers and filters into an in-memory tree, return the number of headers on trunk
    pub fn init_node(&self, blockchain: &mut Blockchain, filters: &mut HashMap<Sha256dHash, (Sha256dHash, u8, Vec<u8>)>) -> Result<u32, SPVError> {
        let mut get_prev = self.tx.prepare("select prev from header where id = ?")?;
        let mut get_header = self.tx.prepare("select data from header where id = ?")?;
        let mut get_filters = self.tx.prepare("select filter_type, filter_id, content from filters where block = ?")?;

        let mut trunk = Vec::new();
        if let Ok(mut current) = self.get_tip() {
            trunk.push(current);
            while current != blockchain.genesis_hash() {
                let prev: Sha256dHash = decode_id(get_prev.query_row(&[&encode_id(&current)?], |r| r.get(0))?)?;
                trunk.push(prev);
                current = prev;
            }
            let mut reverse = trunk.iter().rev();
            reverse.next(); // skip genesis
            for hash in reverse {
                let encoded_hash = &encode_id(hash)?;
                // read header
                blockchain.add_header(decode(get_header.query_row(&[encoded_hash], |r| r.get(0))?)?)?;
                // read filters
                for r in get_filters.query_map(&[encoded_hash],
                        | row | -> Result<(u8, Sha256dHash, Vec<u8>), SPVError> {
                            Ok((row.get(0), decode_id(row.get(1))?, row.get(2)))
                        })? {
                    if let Ok(query) = r {
                        match query {
                            Ok((filter_type, filter_id, content)) => filters.insert(hash.clone(), (filter_id, filter_type, content)),
                            Err(e) => return Err(e)
                        };
                    }
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
    ConsensusDecodable::consensus_decode(&mut decoder).map_err(|e| { SPVError::Util(e) })
}

fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, SPVError>
    where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>> {
    serialize(data).map_err(|e| { SPVError::Util(e) })
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
        assert_eq!(Sha256dHash::default(), tx.get_tip().unwrap());
        tx.set_tip(&Sha256dHash::default()).unwrap();
        assert_eq!(Sha256dHash::default(), tx.get_tip().unwrap());
        let genesis = constants::genesis_block(network::constants::Network::Bitcoin);
        tx.insert_header(&genesis.header).unwrap();
        let header = tx.get_header(&genesis.header.bitcoin_hash()).unwrap();
        assert_eq!(header.bitcoin_hash(), genesis.bitcoin_hash());
        tx.set_tip(&genesis.header.bitcoin_hash()).unwrap();
        tx.commit().unwrap();
    }
}