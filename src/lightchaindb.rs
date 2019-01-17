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
use filterstore::{FilterStore, StoredFilter};
use headercache::HeaderCache;
use filtercache::FilterCache;

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
    path::Path,
    collections::VecDeque
};

pub struct LightChainDB {
    headers_and_filters: BitcoinAdaptor,
    headercache: HeaderCache,
    filtercache: FilterCache,
    network: Network
}

impl LightChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<LightChainDB, SPVError> {
        info!("working with memory database");
        let headers_and_filters = BitcoinAdaptor::new(transient(2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        Ok(LightChainDB { headers_and_filters, headercache: headercache, filtercache, network})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<LightChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let headers_and_filters = BitcoinAdaptor::new(persistent((basename.clone() + ".h").as_str(), 100, 100)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        let db = LightChainDB { headers_and_filters, headercache: headercache, filtercache, network };
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
        let mut sl = VecDeque::new();
        {
            let headers = self.headers();
            if let Some(tip) = headers.fetch_tip()? {
                info!("reading stored header chain from tip {}", tip);
                let mut h = tip;
                while let Some(stored) = headers.fetch(&h)? {
                    sl.push_front(stored.clone());
                    if stored.header.prev_blockhash != Sha256dHash::default() {
                        h = stored.header.prev_blockhash;
                    } else {
                        break;
                    }
                }
                info!("read {} headers", sl.len());
            }
        }

        if sl.is_empty() {
            info!("Initialized with genesis header.");
            let genesis = genesis_block(self.network).header;
            if let Some((stored, _, _)) = self.headercache.add_header (&genesis)? {
                self.headers().store(&stored)?;
                self.headers().store_tip(&stored.bitcoin_hash())?;
            }
        }
        else {
            self.headercache.clear();
            while let Some(stored) = sl.pop_front() {
                self.headercache.add_header_unchecked(&stored);
            }
        }
        Ok(())
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, SPVError> {
        if let Some((stored, unwinds, forward)) = self.headercache.add_header(header)? {
            let mut headers = self.headers();
            headers.store(&stored)?;
            if let Some(forward) = forward.clone() {
                if forward.len () > 0 {
                    headers.store_tip(forward.last().unwrap())?;
                }
            }
            return Ok(Some((stored, unwinds, forward)));
        }
        Ok(None)
    }

    /// is the given hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        self.headercache.is_on_trunk(hash)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<StoredHeader> {
        self.headercache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        self.headercache.get_header(id)
    }

    // locator for getheaders message
    pub fn header_locators(&self) -> Vec<Sha256dHash> {
        self.headercache.locator_hashes()
    }

    pub fn add_filter_chain (&mut self, prev_block_id : &Sha256dHash, prev_filter_id: &Sha256dHash, filter_hashes: impl Iterator<Item=Sha256dHash>) ->
        Result<Option<(Sha256dHash, Sha256dHash)>, SPVError> {
        if let Some(prev_filter) = self.filtercache.get_block_filter(prev_filter_id) {
            if prev_filter.block_id == *prev_block_id {
                let mut previous = *prev_filter_id;
                let mut p_block = *prev_block_id;
                let mut filters = Vec::new();
                for (block_id, filter_hash) in self.headercache.iter_to_tip(prev_block_id).zip(filter_hashes) {
                    let mut buf = [0u8;64];
                    buf[0..32].copy_from_slice(&filter_hash.to_bytes()[..]);
                    buf[32..].copy_from_slice(&previous.to_bytes()[..]);
                    let filter_id = Sha256dHash::from_data(&buf);
                    previous = filter_id;
                    p_block = block_id;
                    let filter = StoredFilter{ block_id, previous, filter_hash, filter: None};
                    filters.push(filter);
                }
                for filter in filters {
                    self.filters().store(&filter)?;
                    self.filtercache.add_filter(filter);
                }
                return Ok(Some((p_block, previous)))
            }
        }
        Ok(None)
    }

    // update if matching stored filter_header chain
    pub fn update_filter (&mut self, block_id: &Sha256dHash, filter: Vec<u8>) -> Result<bool, SPVError> {
        if let Some(filter_header) = self.filtercache.get_block_filter(block_id) {
            let filter_hash = Sha256dHash::from_data(filter.as_slice());
            let mut buf = [0u8;64];
            buf[0..32].copy_from_slice(&filter_hash.to_bytes()[..]);
            buf[32..].copy_from_slice(&filter_header.previous.to_bytes()[..]);
            let filter_id = Sha256dHash::from_data(&buf);
            if filter_id == filter_header.bitcoin_hash() {
                let stored = StoredFilter{block_id: *block_id, previous: filter_header.previous,
                    filter_hash, filter: Some(filter)};
                self.filters().store(&stored)?;
                self.filtercache.add_filter(stored);
                return Ok(true);
            }
        }
        Ok(false)
    }

    // extend filters, only previous filter header must exist
    pub fn add_filter (&mut self, block_id: &Sha256dHash, prev_block_id: &Sha256dHash, filter: Vec<u8>) -> Result<bool, SPVError> {
        if let Some(filter_header) = self.filtercache.get_block_filter(prev_block_id) {
            let filter_hash = Sha256dHash::from_data(filter.as_slice());
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(&filter_hash.to_bytes()[..]);
            buf[32..].copy_from_slice(&filter_header.previous.to_bytes()[..]);
            let filter_id = Sha256dHash::from_data(&buf);
            if filter_id == filter_header.bitcoin_hash() {
                let stored = StoredFilter {
                    block_id: *block_id,
                    previous: filter_header.bitcoin_hash(),
                    filter_hash,
                    filter: Some(filter)
                };
                self.filters().store(&stored)?;
                self.filtercache.add_filter(stored);
                return Ok(true);
            }
        }
        Ok(false)
    }
}
