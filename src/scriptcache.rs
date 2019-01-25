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
    blockdata::transaction::OutPoint,
    blockdata::script::Script,
    util::hash::Sha256dHash
};

use lru_cache::LruCache;

use std::sync::Arc;

pub struct ScriptCache {
    cache: LruCache<OptimizedOutpoint, (Script, Arc<Sha256dHash>)>,
    oldest: Option<Arc<Sha256dHash>>
}

#[derive(Hash, Eq, PartialEq)]
struct OptimizedOutpoint {
    pub txid: Arc<Sha256dHash>,
    pub vout: u32
}

impl ScriptCache {
    pub fn new (capacity: usize) -> ScriptCache {
        ScriptCache{ cache: LruCache::new(capacity), oldest: None }
    }

    pub fn insert (&mut self, txid: Arc<Sha256dHash>, vout: u32, script: Script, block_id: Arc<Sha256dHash>) {
        if self.oldest.is_none () {
            self.oldest = Some(block_id.clone());
        }
        if self.cache.len() == self.cache.capacity () {
            if let Some((k, v)) = self.cache.remove_lru() {
                self.oldest = Some(v.1.clone());
            }
        }
        self.cache.insert(OptimizedOutpoint{txid, vout}, (script, block_id));
    }

    pub fn remove(&mut self, coin: &OutPoint) -> Option<Script> {
        if let Some((s, b)) = self.cache.remove(&OptimizedOutpoint{txid: Arc::new(coin.txid), vout: coin.vout}) {
            return Some(s);
        }
        None
    }

    pub fn oldest_block(&self) -> Option<Sha256dHash> {
        if let Some(ref oldest) = self.oldest {
            return Some(**oldest);
        }
        None
    }
}