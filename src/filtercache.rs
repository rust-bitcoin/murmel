//
// Copyright 2019 Tamas Blummer
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
//! # Cache of block filters
//!

use bitcoin::{
    BitcoinHash,
    blockdata::block::BlockHeader,
    network::constants::Network,
    util::{
        hash::Sha256dHash,
        uint::Uint256,
    },
};
use error::SPVError;
use filterstore::{FilterStore, StoredFilter};
use std::{
    collections::HashMap,
    sync::Arc
};

pub struct FilterCache {
    // all known filters
    filters: HashMap<Arc<Sha256dHash>, StoredFilter>
}

const EXPECTED_CHAIN_LENGTH: usize = 600000;

impl FilterCache {
    pub fn new(network: Network) -> FilterCache {
        FilterCache { filters: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH) }
    }

    /// add a filter with known content
    pub fn add_filter(&mut self, previous: &Sha256dHash, content: &[u8]) -> Result<Option<StoredFilter>, SPVError> {
        if let Some(previous) = self.filters.get(previous) {

            let filter_header = Sha256dHash::from_data(content);
            let mut id_data = [0u8; 64];
            id_data[0..32].copy_from_slice(&filter_header.as_bytes()[..]);
            id_data[0..32].copy_from_slice(&previous.id.as_bytes()[..]);
            let id = Arc::new(Sha256dHash::from_data(&id_data));

            let entry = self.filters.entry(id.clone()).or_insert(
                StoredFilter { id, previous: previous.id.clone(), filter: None }
            );
            entry.filter = Some(content.to_vec());
            return Ok(Some(entry.clone()))
        }
        Ok(None)
    }

    pub fn add_filter_header(&mut self, id: &Sha256dHash, previous: &Sha256dHash) -> Result<Option<StoredFilter>, SPVError> {
        if let Some(previous) = self.filters.get(previous) {
            let stored = StoredFilter { id: Arc::new(id.clone()), previous: previous.id.clone(), filter: None };
            self.filters.insert(stored.id.clone(), stored.clone());
            return Ok(Some(stored));
        }
        Ok(None)
    }


    /// Fetch a header by its id from cache
    pub fn get_filter(&self, id: &Sha256dHash) -> Option<StoredFilter> {
        if let Some(header) = self.filters.get(id) {
            return Some(header.clone());
        }
        None
    }
}
