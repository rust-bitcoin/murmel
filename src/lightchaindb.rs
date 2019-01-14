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
//! # Lightweight Blockchain Database layer for the Bitcoin SPV client
//!
//! Stores headers, filters
//!


use headerstore::{HeaderStore, StoredHeader};
use filterstore::FilterStore;
use chaincache::ChainCache;

use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::BlockHeader,
        constants::genesis_block
    },
    util::hash::Sha256dHash,
    network::constants::Network,
};
use error::SPVError;

use hammersbald::{
    persistent,
    transient,
    BitcoinAdaptor,
    HammersbaldAPI
};


use std::{
    path::Path
};

pub struct LightChainDB {
    headers_and_filters: BitcoinAdaptor,
    chaincache: ChainCache,
    network: Network,
}

impl LightChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<LightChainDB, SPVError> {
        info!("working with memory database");
        let headers_and_filters = BitcoinAdaptor::new(transient(2)?);
        let chaincache = ChainCache::new(network);
        Ok(LightChainDB { headers_and_filters, chaincache, network})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<LightChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let headers_and_filters = BitcoinAdaptor::new(persistent((basename.clone() + ".h").as_str(), 100, 2)?);
        let chaincache = ChainCache::new(network);
        let db = LightChainDB { headers_and_filters, chaincache, network };
        info!("lightchain database {:?} opened", path);
        Ok(db)
    }

    fn headers (&mut self) -> HeaderStore {
        HeaderStore::new(&mut self.headers_and_filters)
    }

    fn filters (&mut self) -> FilterStore {
        FilterStore::new(&mut self.headers_and_filters)
    }

    // Batch writes to hammersbald
    pub fn batch (&mut self) -> Result<(), SPVError> {
        Ok(self.headers_and_filters.batch()?)
    }

    pub fn shutdown (&mut self) {
        self.headers_and_filters.shutdown();
    }

    // read in header and filter chain to cache
    // initialize with genesis block if needed
    pub fn init (&mut self) -> Result<(), SPVError> {
        self.init_headers()
    }

    fn init_headers (&mut self) -> Result<(), SPVError> {
        let mut headers = self.headers();
        if let Some(mut current) = headers.fetch_tip_hash()? {
            self.chaincache.init_cache(&headers)?;
        }
        else {
            let genesis = genesis_block(self.network).header;
            if let Some((stored, _)) = self.chaincache.add_header (&genesis)? {
                headers.store_header(&stored)?;
                headers.store_tip_hash(&stored.header.bitcoin_hash())?;
            }
        }
        Ok(())
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<StoredHeader>, SPVError> {
        if let Some((stored, new_tip)) = self.chaincache.add_header(header)? {
            let mut headers = self.headers();
            headers.store_header(&stored)?;
            if new_tip {
                headers.store_tip_hash(&stored.bitcoin_hash())?;
            }
            return Ok(Some(stored))
        }
        Ok(None)
    }

    /// is the given hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        self.chaincache.is_on_trunk(hash)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<StoredHeader> {
        self.chaincache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        self.chaincache.get_header(id)
    }

    // locator for getheaders message
    pub fn header_locators(&self) -> Vec<Sha256dHash> {
        self.chaincache.locator_hashes()
    }
}
