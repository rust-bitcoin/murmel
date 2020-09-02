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
//! # Blockchain DB for a node
//!

use std::path::Path;

use bitcoin::{BitcoinHash, Network};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;

use bitcoin_hashes::sha256d;

use crate::error::Error;
use crate::headercache::{CachedHeader, HeaderCache};
use log::{debug, info, warn, error};
use crate::chaindb::StoredHeader;
use crate::chaindb::ChainDB;
use rocksdb::DB;

/// Database storing the block chain
pub struct RocksDB {
    db: DB,
    header_cache: HeaderCache,
    network: Network,
}

impl RocksDB {

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<Box<dyn ChainDB>, Error> {
        info!("working with chain db: {}", &path.to_str().unwrap());
        let db = rocksdb::DB::open_default(path).unwrap(); // TODO convert rocksdb::error to murmel::Error
        let header_cache = HeaderCache::new(network);
        Ok(Box::from(RocksDB { db, header_cache, network }))
    }

    fn init_headers(&mut self) -> Result<(), Error> {
        if let Some(tip) = self.fetch_header_tip()? {
            info!("reading stored header chain from tip {}", tip);
            if self.fetch_header(&tip)?.is_some() {
                let mut h = tip;
                while let Some(stored) = self.fetch_header(&h)? {
                    debug!("read stored header {}", &stored.bitcoin_hash());
                    self.header_cache.add_header_unchecked(&h, &stored);
                    if stored.header.prev_blockhash != sha256d::Hash::default() {
                        h = stored.header.prev_blockhash;
                    } else {
                        break;
                    }
                }
                self.header_cache.reverse_trunk();
                info!("read {} headers", self.header_cache.len());
            } else {
                warn!("unable to read header for tip {}", tip);
                self.init_to_genesis()?;
            }
        } else {
            info!("no header tip found");
            self.init_to_genesis()?;
        }
        Ok(())
    }

    fn init_to_genesis(&mut self) -> Result<(), Error> {
        let genesis = genesis_block(self.network).header;
        if let Some((cached, _, _)) = self.header_cache.add_header(&genesis)? {
            info!("initialized with genesis header {}", genesis.bitcoin_hash());
            self.db.put(&cached.stored.bitcoin_hash()[..], serde_cbor::to_vec(&cached.stored).unwrap().as_slice()).unwrap();
            self.store_header_tip(&cached.bitcoin_hash())?;
        } else {
            error!("failed to initialize with genesis header");
            return Err(Error::NoTip);
        }
        Ok(())
    }
}

impl ChainDB for RocksDB {
    /// Initialize caches
    fn init(&mut self) -> Result<(), Error> {
        self.init_headers()?;
        Ok(())
    }

    /// Batch updates. Updates are permanent after finishing a batch.
    fn batch(&mut self) -> Result<(), Error> {
        self.db.flush().unwrap(); // TODO convert rocksdb::error to murmel::Error
        Ok(())
    }

    /// Store a header
    fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<sha256d::Hash>>, Option<Vec<sha256d::Hash>>)>, Error> {
        if let Some((cached, unwinds, forward)) = self.header_cache.add_header(header)? {
            // TODO convert serde_cbor::error::Error and rocksdb::error to murmel::Error
            self.db.put(&cached.stored.bitcoin_hash()[..], serde_cbor::to_vec(&cached.stored).unwrap().as_slice()).unwrap();
            if let Some(forward) = forward.clone() {
                if forward.len() > 0 {
                    self.store_header_tip(forward.last().unwrap())?;
                }
            }
            return Ok(Some((cached.stored, unwinds, forward)));
        }
        Ok(None)
    }

    /// return position of hash on trunk if hash is on trunk
    fn pos_on_trunk(&self, hash: &sha256d::Hash) -> Option<u32> {
        self.header_cache.pos_on_trunk(hash)
    }

    /// iterate trunk [from .. tip]
    fn iter_trunk<'a>(&'a self, from: u32) -> Box<dyn Iterator<Item=&'a CachedHeader> + 'a> {
        self.header_cache.iter_trunk(from)
    }

    /// iterate trunk [genesis .. from] in reverse order from is the tip if not specified
    fn iter_trunk_rev<'a>(&'a self, from: Option<u32>) -> Box<dyn Iterator<Item=&'a CachedHeader> + 'a> {
        self.header_cache.iter_trunk_rev(from)
    }

    /// retrieve the id of the block/header with most work
    fn header_tip(&self) -> Option<CachedHeader> {
        self.header_cache.tip()
    }

    /// Fetch a header by its id from cache
    fn get_header(&self, id: &sha256d::Hash) -> Option<CachedHeader> {
        self.header_cache.get_header(id)
    }

    /// Fetch a header by its id from cache
    fn get_header_for_height(&self, height: u32) -> Option<CachedHeader> {
        self.header_cache.get_header_for_height(height)
    }

    /// locator for getheaders message
    fn header_locators(&self) -> Vec<sha256d::Hash> {
        self.header_cache.locator_hashes()
    }

    /// Store the header id with most work
    fn store_header_tip(&mut self, tip: &sha256d::Hash) -> Result<(), Error> {
        // TODO convert serde_cbor::error::Error and rocksdb::error to murmel::Error
        self.db.put(HEADER_TIP_KEY, serde_cbor::to_vec(&tip).unwrap().as_slice()).unwrap();
        Ok(())
    }

    /// Find header id with most work
    fn fetch_header_tip(&self) -> Result<Option<sha256d::Hash>, Error> {
        // TODO convert serde_cbor::error::Error and rocksdb::error to murmel::Error
        if let Some(value) = self.db.get(HEADER_TIP_KEY).unwrap() {
            Ok(serde_cbor::from_slice(value.as_slice()).unwrap())
        } else {
            Ok(None)
        }
    }

    /// Read header from the DB
    fn fetch_header(&self, id: &sha256d::Hash) -> Result<Option<StoredHeader>, Error> {
        // TODO convert serde_cbor::error::Error and rocksdb::error to murmel::Error
        if let Some(value) = self.db.get(id.to_vec()).unwrap() {
            Ok(serde_cbor::from_slice(value.as_slice()).unwrap())
        } else {
            Ok(None)
        }
    }
}

const HEADER_TIP_KEY:&[u8] = b"HEADER_TIP";

#[cfg(test)]
mod test {
    use bitcoin::{Network, BitcoinHash};
    use bitcoin_hashes::sha256d::Hash;
    use bitcoin::blockdata::constants::genesis_block;

    use log::debug;

    use crate::rocksdb::RocksDB;
    use std::path::{Path, PathBuf};
    use rocksdb::{Options, DB};

    #[test]
    fn add_fetch_header() {
        let network = Network::Testnet;
        let genesis_header = genesis_block(network).header;

        let db_path = DBPath::new("_add_fetch_header_test");
        let path = db_path.path.as_path();
        let mut chaindb = RocksDB::new(path, network).unwrap();

        let genesis = genesis_block(network).header;
        let (stored_header, _unwinds, _forward) = chaindb.add_header(&genesis).unwrap().unwrap();

        let fetched_header = chaindb.fetch_header(&stored_header.bitcoin_hash()).unwrap().unwrap();
        assert_eq!(fetched_header.header, genesis_header);
        assert_eq!(fetched_header.height, 0);
        assert_eq!(fetched_header.log2work, 32.00002201394726);
    }

    #[test]
    fn init_tip_header() {
        //simple_logger::init().unwrap();

        let network = Network::Testnet;
        let genesis_header = genesis_block(network).header;

        let db_path = DBPath::new("_init_tip_header_test");
        let path = db_path.path.as_path();
        let mut chaindb = RocksDB::new(path, network).unwrap();
        debug!("init 1");
        chaindb.init().unwrap();
        debug!("init 2");
        chaindb.init().unwrap();

        let header_tip = chaindb.header_tip();
        assert!(header_tip.is_some(), "failed to get header for tip");
        assert!(header_tip.unwrap().stored.bitcoin_hash().eq(&genesis_header.bitcoin_hash()))
    }

    #[test]
    fn init_recover_if_missing_tip_header() {
        //simple_logger::init().unwrap();

        let network = Network::Testnet;
        let genesis_header = genesis_block(network).header;

        let db_path = DBPath::new("_init_recover_if_missing_tip_header_test");
        let path = db_path.path.as_path();
        let mut chaindb = RocksDB::new(path, network).unwrap();
        let missing_tip_header_hash: Hash = "6cfb35868c4465b7c289d7d5641563aa973db6a929655282a7bf95c8257f53ef".parse().unwrap();
        chaindb.store_header_tip(&missing_tip_header_hash).unwrap();

        chaindb.init().unwrap();

        let header_tip = chaindb.header_tip();
        assert!(header_tip.is_some(), "failed to get header for tip");
        assert!(header_tip.unwrap().stored.bitcoin_hash().eq(&genesis_header.bitcoin_hash()))
    }

    // below is from rust-rocksdb tests/util mod

    /// Temporary database path which calls DB::Destroy when DBPath is dropped.
    pub struct DBPath {
        #[allow(dead_code)]
        dir: tempfile::TempDir, // kept for cleaning up during drop
        path: PathBuf,
    }

    impl DBPath {
        /// Produces a fresh (non-existent) temporary path which will be DB::destroy'ed automatically.
        pub fn new(prefix: &str) -> DBPath {
            let dir = tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("Failed to create temporary path for db.");
            let path = dir.path().join("db");

            DBPath { dir, path }
        }
    }

    impl Drop for DBPath {
        fn drop(&mut self) {
            let opts = Options::default();
            DB::destroy(&opts, &self.path).expect("Failed to destroy temporary DB");
        }
    }

    /// Convert a DBPath ref to a Path ref.
    /// We don't implement this for DBPath values because we want them to
    /// exist until the end of their scope, not get passed in to functions and
    /// dropped early.
    impl AsRef<Path> for &DBPath {
        fn as_ref(&self) -> &Path {
            &self.path
        }
    }
}


