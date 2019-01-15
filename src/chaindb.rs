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

use bitcoin::{
    BitcoinHash,
    network::constants::Network,
    blockdata::block::Block,
};

use hammersbald::PRef;

pub struct ChainDB {
    light: LightChainDB,
    heavy: HeavyChainDB
}

use std::{
    path::Path
};


impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<ChainDB, SPVError> {
        info!("working with memory database");
        let light = LightChainDB::mem(network)?;
        let heavy = HeavyChainDB::mem()?;
        Ok(ChainDB { light, heavy })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<ChainDB, SPVError> {
        let light = LightChainDB::new(path, network)?;
        let heavy = HeavyChainDB::new(path)?;
        info!("chain database {:?} opened", path);
        Ok(ChainDB{light, heavy})
    }

    pub fn init (&mut self) -> Result<(), SPVError> {
        self.light.init()
    }

    // store block if extending trunk
    pub fn extend_blocks (&mut self, block: &Block) -> Result<Option<PRef>, SPVError> {
        let ref block_id = block.bitcoin_hash();
        if self.light.is_on_trunk(block_id) {
            return Ok(None);
        }
        let mut blocks = self.heavy.blocks();
        if let Some (blocks_tip) = blocks.fetch_tip()? {
            if let Some(header) = self.light.get_header(block_id) {
                if header.header.prev_blockhash == blocks_tip {
                    let sref = blocks.store(block)?;
                    blocks.store_tip(block_id)?;
                    return Ok(Some(sref));
                }
            }
        }
        Ok(None)
    }

    // extend UTXO store
    fn extend_utxo (&mut self, block_ref: PRef) -> Result<(), SPVError> {
        let mut utxos = self.heavy.utxos();
        utxos.apply_block(block_ref)
    }

    fn compute_filter(&mut self, block: &Block) -> Result<BlockFilter, SPVError> {
        let mut utxos = self.heavy.utxos().get_utxo_accessor(block)?;
        BlockFilter::compute_wallet_filter(block, utxos)
    }

    pub fn extend_filters (&mut self, block: &Block) -> Result<(), SPVError> {
        if let Some(block_ref) = self.extend_blocks(block)? {
            self.extend_utxo(block_ref)?;
            let filter = self.compute_filter(block)?;
        }
        Ok(())
    }

}