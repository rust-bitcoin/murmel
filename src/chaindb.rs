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

use bitcoin::{
    network::constants::Network
};

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
}