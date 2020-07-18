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

use std::sync::{Arc, RwLock};
use std::path::Path;

use bitcoin::{BitcoinHash, Network};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;

use bitcoin_hashes::sha256d;
use hammersbald::{BitcoinAdaptor, HammersbaldAPI, persistent, transient};

use crate::error::Error;
use crate::headercache::{CachedHeader, HeaderCache};
use log::{debug, info, warn, error};
use serde_derive::{Serialize, Deserialize};

/// Shared handle to a database storing the block chain
/// protected by an RwLock
pub type SharedChainDB = Arc<RwLock<ChainDB>>;

/// Database storing the block chain
pub struct ChainDB {
    db: BitcoinAdaptor,
    headercache: HeaderCache,
    network: Network,
}

impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<ChainDB, Error> {
        info!("working with in memory chain db");
        let db = BitcoinAdaptor::new(transient(2)?);
        let headercache = HeaderCache::new(network);
        Ok(ChainDB { db, network, headercache })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<ChainDB, Error> {
        let basename = path.to_str().unwrap().to_string();
        let db = BitcoinAdaptor::new(persistent((basename.clone()).as_str(), 100, 2)?);
        let headercache = HeaderCache::new(network);
        Ok(ChainDB { db, network, headercache })
    }

    /// Initialize caches
    pub fn init(&mut self) -> Result<(), Error> {
        self.init_headers()?;
        Ok(())
    }

    /// Batch updates. Updates are permanent after finishing a batch.
    pub fn batch(&mut self) -> Result<(), Error> {
        self.db.batch()?;
        Ok(())
    }

    fn init_headers(&mut self) -> Result<(), Error> {
        if let Some(tip) = self.fetch_header_tip()? {
            info!("reading stored header chain from tip {}", tip);
            if self.fetch_header(&tip)?.is_some() {
                let mut h = tip;
                while let Some(stored) = self.fetch_header(&h)? {
                    debug!("read stored header {}", &stored.bitcoin_hash());
                    self.headercache.add_header_unchecked(&h, &stored);
                    if stored.header.prev_blockhash != sha256d::Hash::default() {
                        h = stored.header.prev_blockhash;
                    } else {
                        break;
                    }
                }
                self.headercache.reverse_trunk();
                info!("read {} headers", self.headercache.len());
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
        if let Some((cached, _, _)) = self.headercache.add_header(&genesis)? {
            info!("initialized with genesis header {}", genesis.bitcoin_hash());
            self.db.put_hash_keyed(&cached.stored)?;
            self.db.batch()?;
            self.store_header_tip(&cached.bitcoin_hash())?;
            self.db.batch()?;
        } else {
            error!("failed to initialize with genesis header");
            return Err(Error::NoTip);
        }
        Ok(())
    }

    /// Store a header
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<sha256d::Hash>>, Option<Vec<sha256d::Hash>>)>, Error> {
        if let Some((cached, unwinds, forward)) = self.headercache.add_header(header)? {
            self.db.put_hash_keyed(&cached.stored)?;
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
    pub fn pos_on_trunk(&self, hash: &sha256d::Hash) -> Option<u32> {
        self.headercache.pos_on_trunk(hash)
    }

    /// iterate trunk [from .. tip]
    pub fn iter_trunk<'a>(&'a self, from: u32) -> impl Iterator<Item=&'a CachedHeader> + 'a {
        self.headercache.iter_trunk(from)
    }

    /// iterate trunk [genesis .. from] in reverse order from is the tip if not specified
    pub fn iter_trunk_rev<'a>(&'a self, from: Option<u32>) -> impl Iterator<Item=&'a CachedHeader> + 'a {
        self.headercache.iter_trunk_rev(from)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<CachedHeader> {
        self.headercache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &sha256d::Hash) -> Option<CachedHeader> {
        self.headercache.get_header(id)
    }

    /// Fetch a header by its id from cache
    pub fn get_header_for_height(&self, height: u32) -> Option<CachedHeader> {
        self.headercache.get_header_for_height(height)
    }

    /// locator for getheaders message
    pub fn header_locators(&self) -> Vec<sha256d::Hash> {
        self.headercache.locator_hashes()
    }

    /// Store the header id with most work
    pub fn store_header_tip(&mut self, tip: &sha256d::Hash) -> Result<(), Error> {
        self.db.put_keyed_encodable(HEADER_TIP_KEY, tip)?;
        Ok(())
    }

    /// Find header id with most work
    pub fn fetch_header_tip(&self) -> Result<Option<sha256d::Hash>, Error> {
        Ok(self.db.get_keyed_decodable::<sha256d::Hash>(HEADER_TIP_KEY)?.map(|(_, h)| h.clone()))
    }

    /// Read header from the DB
    pub fn fetch_header(&self, id: &sha256d::Hash) -> Result<Option<StoredHeader>, Error> {
        Ok(self.db.get_hash_keyed::<StoredHeader>(id)?.map(|(_, header)| header))
    }

    /// Shutdown db
    pub fn shutdown(&mut self) {
        self.db.shutdown();
        debug!("shutdown chain db")
    }
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

const HEADER_TIP_KEY: &[u8] = &[0u8; 1];

#[cfg(test)]
mod test {
    use bitcoin::{Network, BitcoinHash};
    use bitcoin_hashes::sha256d::Hash;
    use bitcoin::blockdata::constants::genesis_block;

    use crate::chaindb::ChainDB;

    #[test]
    fn init_tip_header() {
        let network = Network::Testnet;
        let genesis_header = genesis_block(network).header;

        let mut chaindb = ChainDB::mem(network).unwrap();
        chaindb.init().unwrap();
        chaindb.init().unwrap();

        let header_tip = chaindb.header_tip();
        assert!(header_tip.is_some(), "failed to get header for tip");
        assert!(header_tip.unwrap().stored.bitcoin_hash().eq(&genesis_header.bitcoin_hash()))
    }

    #[test]
    fn init_recover_if_missing_tip_header() {
        let network = Network::Testnet;
        let genesis_header = genesis_block(network).header;

        let mut chaindb = ChainDB::mem(network).unwrap();
        let missing_tip_header_hash: Hash = "6cfb35868c4465b7c289d7d5641563aa973db6a929655282a7bf95c8257f53ef".parse().unwrap();
        chaindb.store_header_tip(&missing_tip_header_hash).unwrap();

        chaindb.init().unwrap();

        let header_tip = chaindb.header_tip();
        assert!(header_tip.is_some(), "failed to get header for tip");
        assert!(header_tip.unwrap().stored.bitcoin_hash().eq(&genesis_header.bitcoin_hash()))
    }
}


