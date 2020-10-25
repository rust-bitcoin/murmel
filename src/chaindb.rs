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
//! # Blockchain DB API for a node
//!

use std::sync::{Arc, RwLock};

use bitcoin::BitcoinHash;
use bitcoin::blockdata::block::BlockHeader;

use bitcoin_hashes::sha256d;

use crate::error::Error;
use crate::headercache::CachedHeader;

use serde_derive::{Serialize, Deserialize};

/// Shared handle to a database storing the block chain
/// protected by an RwLock
pub type SharedChainDB = Arc<RwLock<Box<dyn ChainDB>>>;

/// Blockchain DB API for a client node.
pub trait ChainDB: Send + Sync {

    /// Initialize caches.
    fn init(&mut self) -> Result<(), Error>;

    /// Batch updates. Updates are permanent after finishing a batch.
    fn batch(&mut self) -> Result<(), Error>;

    /// Store a header.
    fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<sha256d::Hash>>, Option<Vec<sha256d::Hash>>)>, Error>;

    /// Return position of hash on trunk if hash is on trunk.
    fn pos_on_trunk(&self, hash: &sha256d::Hash) -> Option<u32>;

    /// Iterate trunk [from .. tip].
    fn iter_trunk<'a>(&'a self, from: u32) -> Box<dyn Iterator<Item=&'a CachedHeader> + 'a>;

    /// Iterate trunk [genesis .. from] in reverse order from is the tip if not specified.
    fn iter_trunk_rev<'a>(&'a self, from: Option<u32>) -> Box<dyn Iterator<Item=&'a CachedHeader> + 'a>;

    /// Retrieve the id of the block/header with most work.
    fn header_tip(&self) -> Option<CachedHeader>;

    /// Fetch a header by its id from cache.
    fn get_header(&self, id: &sha256d::Hash) -> Option<CachedHeader>;

    /// Fetch a header by its id from cache.
    fn get_header_for_height(&self, height: u32) -> Option<CachedHeader>;

    /// Locator for getheaders message.
    fn header_locators(&self) -> Vec<sha256d::Hash>;

    /// Store the header id with most work.
    fn store_header_tip(&mut self, tip: &sha256d::Hash) -> Result<(), Error>;

    /// Find header id with most work.
    fn fetch_header_tip(&self) -> Result<Option<sha256d::Hash>, Error>;

    /// Read header from the DB.
    fn fetch_header(&self, id: &sha256d::Hash) -> Result<Option<StoredHeader>, Error>;
}

/// A header enriched with information about its position on the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub log2work: f64,
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredHeader {
    fn bitcoin_hash(&self) -> sha256d::Hash {
        self.header.bitcoin_hash()
    }
}


