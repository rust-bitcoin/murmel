//
// Copyright 2018-2019 Tamas Blummer
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
//! # Configuration Database layer for the Murmel Bitcoin node
//!
//! Stores configuration data.
//!


use bitcoin::network::address::Address;
use error::MurmelError;
use rand;
use rand::RngCore;
use rusqlite;
use rusqlite::{Connection, Error, OpenFlags};
use std::{
    cell::Cell,
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH}
};
use std::sync::{Arc, Mutex};

pub type SharedConfigDB = Arc<Mutex<ConfigDB>>;

pub struct ConfigDB {
    conn: Connection
}

pub struct ConfigTX<'a> {
    tx: rusqlite::Transaction<'a>,
    dirty: Cell<bool>
}

impl ConfigDB {
    /// Create an in-memory database instance
    pub fn mem() -> Result<ConfigDB, MurmelError> {
        info!("working with memory database");
        Ok(ConfigDB { conn: Connection::open_in_memory()?})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path) -> Result<ConfigDB, MurmelError> {
        let db = ConfigDB {
            conn: Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE |
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX)? };
        info!("database {:?} opened", path);
        Ok(db)
    }

    /// Start a transaction. All operations must happen within the context of a transaction
    pub fn transaction<'a>(&'a mut self) -> Result<ConfigTX<'a>, MurmelError> {
        trace!("starting transaction");
        Ok(ConfigTX { tx: self.conn.transaction()?, dirty: Cell::new(false) })
    }
}

impl<'a> ConfigTX<'a> {
    /// commit the transaction
    pub fn commit(self) -> Result<(), MurmelError> {
        if self.dirty.get() {
            self.tx.commit()?;
            trace!("committed transaction");
        }
        Ok(())
    }

    /// rollback the transaction
    #[allow(unused)]
    pub fn rollback(self) -> Result<(), MurmelError> {
        self.tx.rollback()?;
        trace!("rolled back transaction");
        Ok(())
    }

    /// Create tables for configuration data
    pub fn create_tables(&mut self) -> Result<(), MurmelError> {
        trace!("creating tables...");
        self.dirty.set(true);

        self.tx.execute("create table if not exists peers (
                                address text primary key,
                                port integer,
                                services integer,
                                last_seen integer,
                                banned_until integer)", &[])?;


        self.tx.execute("create table if not exists birth (inception integer)", &[])?;
        trace!("created tables");
        Ok(())
    }


    pub fn get_birth(&self) -> Result<Option<u64>, MurmelError> {
        if let Ok(time) = self.tx.query_row::<i64, _>("select inception from birth",
                             &[],
                             |row| {
                                 row.get(0)
                             }) {
            Ok(Some(time as u64))
        }
        else {
            Ok(None)
        }
    }

    pub fn set_birth(&mut self, birth: u64) -> Result<(), MurmelError> {
        if self.get_birth()?.is_none() {
            self.tx.execute("insert into birth (inception) values (?)", &[&(birth as i64)])?;
        }
        else {
            info!("Ignoring request to set birth time point, birth is already set to {}", self.get_birth()?.unwrap());
        }
        Ok(())
    }

    /// store a peer
    ///   * last_seen - in unix epoch seconds
    ///   * banned_until - in unix epoch seconds
    ///   * speed - in ms as measured with ping
    pub fn store_peer (&mut self, address: &Address, last_seen: u32, banned_until: u32) -> Result<(), MurmelError> {
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

    #[allow(unused)]
    pub fn ban (&mut self, addr: &SocketAddr) -> Result<i32, MurmelError> {
        self.dirty.set(true);
        let address = Address::new (addr, 0);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }
        let banned_until = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 + 2*24*60;
        Ok(self.tx.execute("update peers set banned_until = ? where address = ?", &[&banned_until, &s])?)
    }

    #[allow(unused)]
    pub fn remove_peer (&mut self, addr: &SocketAddr) -> Result<i32, MurmelError> {
        self.dirty.set(true);
        let address = Address::new (addr, 0);
        let mut s = String::new();
        for d in address.address.iter() {
            s.push_str(format!("{:4x}",d).as_str());
        }
        Ok(self.tx.execute("delete from peers where address = ?", &[&s])?)
    }

    /// get a random stored peer
    pub fn get_a_peer (&self, earlier: &HashSet<SocketAddr>) -> Result<Address, MurmelError> {
        let n_peers: i64 = self.tx.query_row(
            "select count(*) from peers", &[], | row | { row.get(0) })?;

        if n_peers == 0 {
            return Err(MurmelError::NoPeers);
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
        Err(MurmelError::NoPeers)
    }
}
