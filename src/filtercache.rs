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
    BitcoinHash,
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
    filters: HashMap<Sha256dHash, Arc<StoredFilter>>,
    server: bool
}

const EXPECTED_CHAIN_LENGTH: usize = 600000;

#[allow(unused)]
impl FilterCache {
    pub fn new(server: bool) -> FilterCache {
        FilterCache { filters: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH),
            by_block: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH), server }
    }

    pub fn len (&self) -> usize {
        self.filters.len()
    }

    pub fn add_filter(&mut self, filter: &StoredFilter) {
        if self.server {
            let filter = Arc::new(filter.clone());
            self.by_block.insert((filter.block_id, filter.filter_type), filter.clone());
            self.filters.insert(filter.filter_id(), filter);
        } else {
            let mut stored = filter.clone();
            stored.filter = None;
            let filter = Arc::new(stored.clone());
            self.by_block.insert((filter.block_id, stored.filter_type), filter.clone());
            self.filters.insert(filter.filter_id(), filter);
        }
    }

    /// Fetch a header by its id from cache
    pub fn get_filter(&self, filter_id: &Sha256dHash) -> Option<StoredFilter> {
        self.filters.get(filter_id).map(|b|{(**b).clone()})
    }

    pub fn get_block_filter(&self, block_id: &Sha256dHash, filter_type: u8) -> Option<StoredFilter> {
        self.by_block.get(&(*block_id, filter_type)).map(|b|{(**b).clone()})
    }

    /// iterate from id to genesis
    pub fn iter_from<'a> (&'a self, id: &Sha256dHash) -> FilterIterator<'a> {
        return FilterIterator::new(self, id)
    }
}

pub struct FilterIterator<'a> {
    current: Sha256dHash,
    cache: &'a FilterCache
}

impl<'a> FilterIterator<'a> {
    pub fn new (cache: &'a FilterCache, tip: &Sha256dHash) -> FilterIterator<'a> {
        FilterIterator { current: *tip, cache }
    }
}

impl<'a> Iterator for FilterIterator<'a> {
    type Item = Sha256dHash;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.current == Sha256dHash::default() {
            return None;
        }
        if let Some (filter) = self.cache.filters.get(&self.current) {
            let current = self.current;
            self.current = filter.previous;
            return Some(current)
        }
        return None;
    }
}