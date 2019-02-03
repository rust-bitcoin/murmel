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
//! # Cache output scripts for coins
//!


use bitcoin::{
    blockdata::script::Script,
    blockdata::transaction::OutPoint
};
use lru_cache::LruCache;
use std::{
    cmp::max
};

pub struct ScriptCache {
    cache: LruCache<OutPoint, (Script, u32)>,
    complete_after: u32
}

impl ScriptCache {
    pub fn new (capacity: usize) -> ScriptCache {
        ScriptCache{ cache: LruCache::new(capacity), complete_after: 0 }
    }

    pub fn insert (&mut self, coin: OutPoint, script: Script, height: u32) {
        if self.complete_after == 0 || self.cache.capacity() == 0 {
            self.complete_after = height;
        }
        if self.cache.len() == self.cache.capacity () {
            if let Some((_, (_, lru_height))) = self.cache.remove_lru() {
                self.complete_after = max(self.complete_after, lru_height);
            }
        }
        self.cache.insert(coin, (script, height));
    }

    pub fn remove(&mut self, coin: &OutPoint) -> Option<Script> {
        if let Some((s, _)) = self.cache.remove(coin) {
            return Some(s);
        }
        None
    }

    pub fn len(&self) -> usize { self.cache.len() }

    pub fn capacity(&self) -> usize { self.cache.capacity() }

    pub fn complete_after(&self) -> u32 {
        self.complete_after
    }
}