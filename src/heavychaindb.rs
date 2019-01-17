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
use utxostore::UTXOStore;

use bitcoin::{
    util::hash::Sha256dHash
};

use hammersbald::{
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

    pub fn blocks (&mut self) -> BlockStore {
        BlockStore::new(&mut self.blocks_and_utxos)
    }

    pub fn utxos (&mut self) -> UTXOStore {
        UTXOStore::new(&mut self.blocks_and_utxos)
    }

    pub fn unwind_utxo (&mut self, block_id: &Sha256dHash) -> Result<(), SPVError> {
        let mut utxos = self.utxos();
        utxos.unwind(block_id)
    }

    pub fn unwind_tip (&mut self, ut: &Sha256dHash) -> Result<bool, SPVError> {
        if let Some(tip) = self.blocks().fetch_tip()? {
            // unwind might happen before block was actually applied
            // ignore unwind in this case
            if *ut == tip {
                self.unwind_utxo(&tip)?;
                return Ok(true);
            }
        }
        Ok(false)
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
