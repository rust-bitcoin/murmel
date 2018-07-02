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


use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use bitcoin::network::serialize::{RawDecoder, RawEncoder};
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::network::serialize::serialize;
use bitcoin::network::address::Address;
use bitcoin::util::hash::Sha256dHash;
use error::SPVError;
use rusqlite;
use rusqlite::Connection;
use rusqlite::Error;
use rusqlite::OpenFlags;
use std::io::Cursor;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::net::SocketAddr;
use rand;
use rand::Rng;

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
                                id blob(32)
                                )", &[])?;

        self.tx.execute("create table if not exists header (
                                id blob(32) primary key,
                                data blob
                                )", &[])?;

        self.tx.execute("create table if not exists tx (
                                id blob(32) primary key,
                                data blob
                                )", &[])?;

        self.tx.execute("create table if not exists peers (
                                address text primary key,
                                port integer,
                                services integer,
                                last_seen integer,
                                banned_until integer)", &[])?;

        self.tx.execute("create table if not exists filters (
                                id blob(32) primary key,
                                prev_id blob(32),
                                content blob)", &[])?;

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
    pub fn get_a_peer (&self) -> Result<Address, SPVError> {
        let n_peers: i64 = self.tx.query_row(
            "select count(*) from peers", &[], | row | { row.get(0) })?;

        if n_peers == 0 {
            return Err(SPVError::Generic("no peers in the database"));
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
                return Ok(Address {
                    address: v,
                    port: a.1,
                    services: a.2 as u64
                })
            }
        }
        Err(SPVError::Generic("no useful peers in the database"))
    }

    /// Set the highest hash for the chain with most work
    pub fn set_tip(&self, hash: &Sha256dHash) -> Result<(), SPVError> {
        trace!("storing tip {}", hash);
        self.tx.execute("delete from tip", &[]).map(|_| { () })?;
        Ok(self.tx.execute("insert into tip (id) values (?)", &[&encode(hash)?]).map(|_| { () })?)
    }

    /// Get the hash of the highest hash on the chain with most work
    pub fn get_tip(&self) -> Result<Sha256dHash, SPVError> {
        decode(self.tx.query_row("select id from tip where rowid = 1",
                                        &[], |row| { row.get(0) })?)
    }

    /// Store a header into the DB. This method will return an error if the header is already stored.
    pub fn insert_header(&self, header: &BlockHeader) -> Result<(), SPVError> {
        let hash = header.bitcoin_hash();
        self.tx.execute("insert into header (id, data) values (?, ?)",
                        &[&encode(&hash)?, &encode(header)?])?;
        trace!("stored header {}", hash);
        Ok(())
    }

    /// Get a stored header. This method will return an error for an unknown header.
    pub fn get_header(&self, hash: &Sha256dHash) -> Result<BlockHeader, SPVError> {
        decode(self.tx.query_row("select data from header where id = ?",
                                 &[&encode(hash)?], |row| { row.get(0) })?)
    }

    /// Insert a transaction. This method will NOT return an error if the transaction is already known.
    pub fn insert_transaction(&self, transaction: &Transaction) -> Result<(), SPVError> {
        if let Ok(_) = self.get_transaction(&transaction.txid()) {
            Ok(())
        } else {
            let hash = transaction.txid();
            self.tx.execute("insert into tx (id, data) values (?, ?)",
                            &[&encode(&hash)?, &encode(transaction)?])?;
            Ok(())
        }
    }

    /// Retrieve a stored transaction. This method will return an error if the transaction was not stored
    #[allow(dead_code)]
    pub fn get_transaction(&self, hash: &Sha256dHash) -> Result<Transaction, SPVError> {
        decode(self.tx.query_row("select data from tx where id = ?",
                                 &[&encode(hash)?], |row| { row.get(0) })?)
    }

    /// Return headers in ascending hight order. (genesis, tip]
    pub fn get_headers(&self, genesis: &Sha256dHash, tip: &Sha256dHash) -> Result<Vec<BlockHeader>, SPVError> {
        let mut result = Vec::new();
        let mut current = *tip;
        while current != *genesis {
            let header = self.get_header(&current)?;
            result.push(header);
            current = header.prev_blockhash;
        }
        result.reverse();
        Ok(result)
    }
}

fn decode<T: ? Sized>(data: Vec<u8>) -> Result<T, SPVError>
    where T: ConsensusDecodable<RawDecoder<Cursor<Vec<u8>>>> {
    let mut decoder: RawDecoder<Cursor<Vec<u8>>> = RawDecoder::new(Cursor::new(data));
    Ok(ConsensusDecodable::consensus_decode(&mut decoder)
        .map_err(|_| { Error::InvalidParameterName("serialization error".to_owned()) })?)
}


fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, SPVError>
    where T: ConsensusEncodable<RawEncoder<Cursor<Vec<u8>>>> {
    Ok(serialize(data)
        .map_err(|_| { Error::InvalidParameterName("serialization error".to_owned()) })?)
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