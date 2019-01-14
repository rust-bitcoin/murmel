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
//! # Heavy Blockchain Database layer for the Bitcoin SPV client
//!
//! Stores blocks, utxos
//!


use error::SPVError;

use blockstore::BlockStore;
use utxostore::{DBUTXOAccessor, UTXOStore};
use lightchaindb::LightChainDB;

use bitcoin::{
    BitcoinHash,
    util::hash::Sha256dHash,
    blockdata::block::Block
};

use hammersbald::{
    PRef,
    persistent,
    transient,
    BitcoinAdaptor,
    HammersbaldAPI
};


use std::{
    path::Path
};

pub struct HeavyChainDB {
    blocks_and_utxos: BitcoinAdaptor
}

impl HeavyChainDB {
    /// Create an in-memory database instance
    pub fn mem() -> Result<HeavyChainDB, SPVError> {
        info!("working with memory database");
        let blocks = BitcoinAdaptor::new(transient( 2)?);
        Ok(HeavyChainDB { blocks_and_utxos: blocks})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path) -> Result<HeavyChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let blocks = BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 100, 100)?);
        let db = HeavyChainDB { blocks_and_utxos: blocks };
        info!("heavy block database {:?} opened", path);
        Ok(db)
    }

    fn blocks (&mut self) -> BlockStore {
        BlockStore::new(&mut self.blocks_and_utxos)
    }

    fn utxos (&mut self) -> UTXOStore {
        UTXOStore::new(&mut self.blocks_and_utxos)
    }

    // store block if extending trunk
    pub fn extend_blocks (&mut self, light: &LightChainDB, block: &Block) -> Result<Option<PRef>, SPVError> {
        let ref block_id = block.bitcoin_hash();
        if light.is_on_trunk(block_id) {
            return Ok(None);
        }
        let mut blocks = self.blocks();
        if let Some (blocks_tip) = blocks.fetch_tip()? {
            if let Some(header) = light.get_header(block_id) {
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
    pub fn extend_utxo (&mut self, block_ref: PRef) -> Result<(), SPVError> {
        let mut utxos = self.utxos();
        utxos.apply_block(block_ref)
    }

    pub fn unwind_utxo (&mut self, block_id: &Sha256dHash) -> Result<(), SPVError> {
        let mut utxos = self.utxos();
        utxos.unwind(block_id)
    }

    pub fn get_utxo_accessor<'a>(&'a mut self, block: &Block) -> Result<DBUTXOAccessor<'a>, SPVError> {
        self.utxos().get_utxo_accessor(block)
    }

    // Batch writes to hammersbald
    pub fn batch (&mut self) -> Result<(), SPVError> {
        Ok(self.blocks_and_utxos.batch()?)
    }

    /// Shutdown hammersbald
    pub fn shutdown (&mut self) {
        self.blocks_and_utxos.shutdown();
    }
}
