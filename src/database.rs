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
use blockfilter::BlockFilter;
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
                                headers blob(32),
                                filters blob(32)
                                )", &[])?;

        self.tx.execute("create table if not exists header (
                                id blob(32) primary key,
                                prev blob(32),
                                data blob
                                )", &[])?;

        self.tx.execute("create table if not exists utxo (
                                id blob(32),
                                ix integer,
                                script blob,
                                amount integer,
                                block blob(32),
                                primary key(id, ix)
                                )", &[])?;

        self.tx.execute("create index if not exists utxo_block on utxo (block)", &[])?;

        self.tx.execute("create table if not exists utxo_unwind (
                                id blob(32),
                                ix integer,
                                script blob,
                                amount integer,
                                was_block blob(32),
                                block blob(32),
                                primary key(id, ix)
                                )", &[])?;

        self.tx.execute("create index if not exists utxo_unwind_block on utxo_unwind (block)", &[])?;

        self.tx.execute("create table if not exists unwindable (
                                id blob(32)
                                )", &[])?;

        self.tx.execute("create table if not exists peers (
                                address text primary key,
                                port integer,
                                services integer,
                                last_seen integer,
                                banned_until integer)", &[])?;

        self.tx.execute("create table if not exists filters (
                                block blob(32),
                                filter_type integer,
                                filter_id blob(32),
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
    pub fn set_tip(&self, headers: &Sha256dHash) -> Result<(), SPVError> {
        trace!("storing tip {}", headers);
        self.tx.execute("delete from tip", &[]).map(|_| { () })?;
        Ok(self.tx.execute("insert into tip (headers) values (?)", &[&encode(headers)?]).map(|_| { () })?)
    }

    /// Get the hash of the highest hash on the chain with most work
    pub fn get_tip(&self) -> Result<Sha256dHash, SPVError> {
        decode(self.tx.query_row("select headers from tip",
                                        &[], |row| { row.get(0) })?)
    }

    /// Store a header into the DB. This method will return an error if the header is already stored.
    pub fn insert_header(&self, header: &BlockHeader) -> Result<(), SPVError> {
        let hash = header.bitcoin_hash();
        self.tx.execute("insert into header (id, prev, data) values (?, ?, ?)",
                        &[&encode(&hash)?, &encode(&header.prev_blockhash)?, &encode(header)?])?;
        Ok(())
    }

    /// Get a stored header. This method will return an error for an unknown header.
    pub fn get_header(&self, hash: &Sha256dHash) -> Result<BlockHeader, SPVError> {
        decode(self.tx.query_row("select data from header where id = ?",
                                 &[&encode(hash)?], |row| { row.get(0) })?)
    }

    pub fn previous_processed (&self, block: &Block) -> Result<bool, SPVError> {
        let prev_block = block.header.prev_blockhash;
        if prev_block == Sha256dHash::default() {
            return Ok(true)
        }
        match self.tx.query_row("select id from filters where block = ?", &[&encode(&prev_block)?], |_| true ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false)
        }
    }

    /// Retrieve a stored transaction. This method will return an error if the transaction was not stored
    pub fn get_utxo(&self, hash: &Sha256dHash, ix: u32) -> Result<(Script, u64), SPVError> {
        let r = self.tx.query_row("select script, amount from utxo where id = ? and ix = ?",
                                 &[&encode(hash)?, &ix],
                             |row| -> Result<(Script, i64), SPVError> { Ok((decode(row.get(0))?, row.get(1))) })?;
        match r {
            Err(e) => Err(e),
            Ok((s, v)) => Ok((s, v as u64))
        }
    }


    pub fn update_utxos(&self, block: &Block) -> Result<(), SPVError> {
        debug!("add utxos for {}", block.bitcoin_hash());
        let block_id = &encode(&block.bitcoin_hash())?;

        let mut insert_unwind = self.tx.prepare("insert into utxo_unwind (id, ix, script, amount, was_block, block) values (?, ?, ?, ?, ?, ?)")?;
        let mut insert_utxo = self.tx.prepare("insert into utxo (id, ix, script, amount, block) values (?, ?, ?, ?, ?)")?;
        let mut delete_utxo = self.tx.prepare("delete from utxo where id = ? and ix = ?")?;
        let mut get_utxo = self.tx.prepare("select script, amount, block from utxo where id = ? and ix = ?")?;

        for transaction in &block.txdata {
            let txid = transaction.txid();
            let txhash = &encode(&txid)?;

            for (ix, out) in transaction.output.iter().enumerate() {
                if !out.script_pubkey.is_op_return() {
                    insert_utxo.execute(&[txhash, &(ix as u32), &encode(&out.script_pubkey.data())?, &(out.value as i64), block_id])?;
                }
            }
            if !transaction.is_coin_base() {
                for input in &transaction.input {
                    let prev = &encode(&input.prev_hash)?;
                    delete_utxo.execute(&[prev, &input.prev_index])?;

                    if let Ok(spent) = get_utxo.query_row(&[&encode(&input.prev_hash)?, &input.prev_index],
                                       |row| -> Result<(Script, i64, Sha256dHash), SPVError> {
                                           Ok((decode(row.get(0))?, row.get(1), decode(row.get(2))?))}) {
                        if let Ok((script, amount, was_block)) = spent {
                            insert_unwind.execute(&[prev, &(input.prev_index),
                                &script.data(), &amount, &encode(&was_block)?, block_id])?;
                        }
                    }
                }
            }
        }
        self.tx.execute("insert into unwindable (id) values (?)", &[block_id])?;
        let forget = self.tx.last_insert_rowid() - UNWIND_LIMIT;
        if forget > 0 {
            if let Ok(blob) = self.tx.query_row("select id from unwindable where rowid = ?", &[&forget], |row| -> Vec<u8> { row.get(0) } ) {
                self.tx.execute("delete from utxo_unwind where block = ?", &[&blob])?;
                self.tx.execute("delete from unwindable where id = ?", &[&blob])?;
            }
        }
        Ok(())
    }

    pub fn unwind_utxos(&self, block_hash: &Sha256dHash) -> Result<(), SPVError> {
        debug!("unwind utxos for {}", block_hash);
        let block_id = &encode(block_hash)?;
        self.tx.execute("delete from utxo where block = ?", &[&encode(block_id)?])?;
        self.tx.execute("insert into utxo (id, ix, script, amount, block)
                              select id, ix, script, amount, was_block from utxo_unwind
                              where block = ?", &[block_id])?;
        Ok(())
    }

    /// read headers into an in-memory tree, return the number of headers on trunk
    pub fn get_headers(&self, blockchain: &mut Blockchain) -> Result<u32, SPVError> {
        let mut get_prev = self.tx.prepare("select prev from header where id = ?")?;
        let mut get_header = self.tx.prepare("select data from header where id = ?")?;

        let mut trunk = Vec::new();
        if let Ok(mut current) = self.get_tip() {
            trunk.push(current);
            while current != blockchain.genesis_hash() {
                let prev: Sha256dHash = decode(get_prev.query_row(&[&encode(&current)?], |r| r.get(0))?)?;
                trunk.push(prev);
                current = prev;
            }
            let mut reverse = trunk.iter().rev();
            reverse.next(); // skip genesis
            for hash in reverse {
                blockchain.add_header(decode(get_header.query_row(&[&encode(hash)?], |r| r.get(0))?)?)?;
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