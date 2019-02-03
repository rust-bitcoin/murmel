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
//! # Cache of block filters
//!

use bitcoin::{
    util::{
        hash::Sha256dHash
    },
};
use chaindb::StoredFilter;
use std::{
    collections::HashMap,
    sync::Arc
};

pub struct FilterCache {
    // filters by block_id
    by_block: HashMap<(Sha256dHash, u8), Arc<StoredFilter>>,
    // all known filters
    filters: HashMap<Sha256dHash, Arc<StoredFilter>>
}

const EXPECTED_CHAIN_LENGTH: usize = 600000;

impl FilterCache {
    pub fn new() -> FilterCache {
        FilterCache { filters: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH),
            by_block: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH) }
    }

    pub fn len (&self) -> usize {
        self.filters.len()
    }

    pub fn add_filter_header(&mut self, filter: &StoredFilter) -> Option<Arc<StoredFilter>> {
        let mut stored = filter.clone();
        stored.filter = None;
        let filter = Arc::new(stored);
        self.by_block.insert((filter.block_id, filter.filter_type), filter.clone());
        self.filters.insert(filter.filter_id(), filter)
    }

    /// Fetch a header by its id from cache
    pub fn get_filter_header(&self, filter_id: &Sha256dHash) -> Option<Arc<StoredFilter>> {
        self.filters.get(filter_id).map(|b|{(*b).clone()})
    }

    pub fn get_block_filter_header(&self, block_id: &Sha256dHash, filter_type: u8) -> Option<Arc<StoredFilter>> {
        self.by_block.get(&(*block_id, filter_type)).map(|b|{(*b).clone()})
    }
}
