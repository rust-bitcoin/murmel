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

use lightchaindb::LightChainDB;
use heavychaindb::HeavyChainDB;
use error::SPVError;
use blockfilter::BlockFilter;
use headerstore::StoredHeader;
use utxostore::DBUTXOAccessor;

use bitcoin::{
    BitcoinHash,
    network::constants::Network,
    blockdata::{
        block::{BlockHeader, Block},
        constants::genesis_block
    },
    util::hash::Sha256dHash,
};

use hammersbald::PRef;

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
        if self.heavy.is_some() {
            let genesis = genesis_block(self.network);
            if let Some(tip) = self.light.header_tip() {
                if genesis.header.bitcoin_hash() == tip.bitcoin_hash() {
                    self.extend_blocks_utxo_filters(&genesis)?;
                    info!("Initialized with genesis block.");
                }
            }
        }
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

    // store block if extending trunk
    pub fn extend_blocks (&mut self, block: &Block) -> Result<Option<PRef>, SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let ref block_id = block.bitcoin_hash();

            // do not store if not on trunk
            if !self.light.is_on_trunk(block_id) {
                return Ok(None);
            }
            // do not store if already stored
            if let Some((sref, _)) = heavy.blocks().fetch(&block.bitcoin_hash())? {
                return Ok(Some(sref));
            }

            if let Some(blocks_tip) = heavy.blocks().fetch_tip()? {
                // header must be known in advance
                if let Some(header) = self.light.get_header(block_id) {
                    // store
                    let sref = heavy.blocks().store(block)?;
                    // move tip if next on trunk
                    if header.header.prev_blockhash == blocks_tip {
                        heavy.blocks().store_tip(block_id)?;
                    }
                    return Ok(Some(sref));
                }
            }
            else {
                // init empty db with genesis block
                let sref = heavy.blocks().store(block)?;
                heavy.blocks().store_tip(block_id)?;
                return Ok(Some(sref));
            }
        }
        else {
            panic!("configuration error: no heavy chain db");
        }
        Ok(None)
    }

    // extend UTXO store
    fn extend_utxo (&mut self, block_ref: PRef) -> Result<(), SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let mut utxos = heavy.utxos();
            utxos.apply_block(block_ref)?;
        }
        Ok(())
    }

    fn compute_filter(&mut self, block: &Block) -> Result<Option<BlockFilter>, SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let utxos = heavy.utxos();
            let accessor = DBUTXOAccessor::new(&utxos, block)?;
            return Ok(Some(BlockFilter::compute_wallet_filter(block, accessor)?));
        }
        Ok(None)
    }

    pub fn extend_blocks_utxo_filters (&mut self, block: &Block) -> Result<(), SPVError> {
        if self.heavy.is_some() {
            if let Some(block_ref) = self.extend_blocks(block)? {
                if let Some(filter) = self.compute_filter(block)? {
                    self.light.add_filter(&block.bitcoin_hash(), &block.header.prev_blockhash, filter.content)?;
                }
                self.extend_utxo(block_ref)?;
            }
        }
        else {
            panic!("configuration error: no heavy chain db");
        }
        Ok(())
    }

    pub fn unwind_tip (&mut self, tip: &Sha256dHash) -> Result<bool, SPVError> {
        // light chain unwind is implicit through add_header
        if let Some(ref mut heavy) = self.heavy {
            return Ok(heavy.unwind_tip(tip)?);
        }
        Ok(false)
    }
}