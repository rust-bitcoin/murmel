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


use bitcoin::network::constants::Network;
use error::SPVError;

use hammersbald::{
    persistent,
    transient,
    BitcoinAdaptor,
    HammersbaldAPI
};


use blockstore::BlockStore;
use utxostore::UTXOStore;

use std::{
    path::Path
};

pub struct HeavyChainDB {
    blocks_and_utxos: BitcoinAdaptor,
    network: Network,
}

impl HeavyChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<HeavyChainDB, SPVError> {
        info!("working with memory database");
        let blocks = BitcoinAdaptor::new(transient( 2)?);
        Ok(HeavyChainDB { blocks_and_utxos: blocks, network})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<HeavyChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let blocks = BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 100, 2)?);
        let db = HeavyChainDB { blocks_and_utxos: blocks, network };
        info!("heavy block database {:?} opened", path);
        Ok(db)
    }

    fn blocks (&mut self) -> BlockStore {
        BlockStore::new(&mut self.blocks_and_utxos)
    }

    fn utxos (&mut self) -> UTXOStore {
        UTXOStore::new(&mut self.blocks_and_utxos)
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
