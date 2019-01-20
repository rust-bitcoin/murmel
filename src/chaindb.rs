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

use lightchaindb::{LightChainDB, StoredHeader};
use headercache::{HeaderIterator, TrunkIterator};
use heavychaindb::{HeavyChainDB, DBUTXOAccessor};
use error::SPVError;
use blockfilter::BlockFilter;

use bitcoin::{
    BitcoinHash,
    network::constants::Network,
    blockdata::{
        block::{BlockHeader, Block},
        constants::genesis_block
    },
    util::hash::Sha256dHash,
};

use std::sync::{Arc, RwLock};

use hammersbald::PRef;

pub type SharedChainDB = Arc<RwLock<ChainDB>>;

pub struct ChainDB {
    light: LightChainDB,
    heavy: Option<HeavyChainDB>,
    network: Network
}

use std::{
    path::Path
};


impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network, heavy: bool) -> Result<ChainDB, SPVError> {
        let light = LightChainDB::mem(network)?;
        if heavy {
            Ok(ChainDB { light, heavy: Some(HeavyChainDB::mem()?), network })
        }
        else {
            Ok(ChainDB { light, heavy: None, network})
        }
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network, heavy: bool) -> Result<ChainDB, SPVError> {
        let light = LightChainDB::new(path, network)?;
        if heavy {
            Ok(ChainDB { light, heavy: Some(HeavyChainDB::new(path)?), network })
        }
        else {
            Ok(ChainDB { light, heavy: None, network})
        }
    }

    pub fn init (&mut self) -> Result<(), SPVError> {
        self.light.init()?;
        Ok(())
    }

    pub fn batch(&mut self) -> Result<(), SPVError> {
        self.light.batch()?;
        if let Some(ref mut heavy) = self.heavy {
            heavy.batch()?;
        }
        Ok(())
    }

    pub fn tip (&self) -> Option<StoredHeader> {
        self.light.header_tip()
    }

    pub fn header_locators (&self) -> Vec<Sha256dHash> {
        self.light.header_locators()
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, SPVError> {
        self.light.add_header(header)
    }

    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        self.light.get_header(id)
    }

    pub fn iter_to_genesis<'a>(&'a self, id: &Sha256dHash) -> HeaderIterator<'a> {
        return self.light.iter_to_genesis(id)
    }

    pub fn iter_trunk_to_genesis<'a>(&'a self) -> HeaderIterator<'a> {
        return self.light.iter_trunk_to_genesis()
    }

    pub fn iter_to_tip<'a>(&'a self, id: &Sha256dHash) -> TrunkIterator<'a> {
        return self.light.iter_to_tip(id)
    }

    pub fn store_block(&mut self, block: &Block) -> Result<(), SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let block_ref = heavy.store_block(block)?;
            self.light.update_header_with_block(&block.bitcoin_hash(), block_ref)?;
        }
        Ok(())
    }

    // extend UTXO store
    fn extend_utxo (&mut self, block_ref: PRef) -> Result<(), SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let mut utxos = heavy.apply_block(block_ref)?;
        }
        Ok(())
    }

    fn compute_filter(&mut self, block: &Block) -> Result<Option<BlockFilter>, SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let accessor = DBUTXOAccessor::new(&heavy, block)?;
            return Ok(Some(BlockFilter::compute_wallet_filter(block, accessor)?));
        }
        Ok(None)
    }
}