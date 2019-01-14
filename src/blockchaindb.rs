//
// Copyright 2019 Tamas Blummer
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
//! # Blockchain Database layer for the Bitcoin SPV client
//!
//! Stores headers, filters, blocks
//!


use bitcoin::network::constants::Network;
use bitcoin::util::hash::Sha256dHash;
use error::SPVError;

use hammersbald::{
    persistent,
    transient,
    BitcoinAdaptor,
    HammersbaldAPI
};


use headerstore::HeaderStore;
use filterstore::FilterStore;
use blockstore::BlockStore;
use utxostore::UTXOStore;

use std::{
    path::Path
};

/// Database interface to connect
/// start, commit or rollback transactions
/// # Example
/// let mut db = DB::mem();
/// let tx = db.transaction();
/// //... database operations through tx
/// tx.commit();
pub struct BlockchainDB {
    headers_and_filters: BitcoinAdaptor,
    blocks: BitcoinAdaptor,
    network: Network,
}

impl BlockchainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network) -> Result<BlockchainDB, SPVError> {
        info!("working with memory database");
        let blocks = BitcoinAdaptor::new(transient( 2)?);
        let headers_and_filters = BitcoinAdaptor::new(transient(2)?);
        Ok(BlockchainDB { headers_and_filters, blocks, network})
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network) -> Result<BlockchainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let headers_and_filters = BitcoinAdaptor::new(persistent((basename.clone() + ".h").as_str(), 100, 2)?);
        let blocks = BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 100, 2)?);
        let db = BlockchainDB { headers_and_filters, blocks, network };
        info!("block database {:?} opened", path);
        Ok(db)
    }

    pub fn headers (&mut self) -> HeaderStore {
        HeaderStore::new(&mut self.headers_and_filters)
    }

    pub fn filters (&mut self) -> FilterStore {
        FilterStore::new(&mut self.headers_and_filters)
    }

    pub fn blocks (&mut self) -> BlockStore {
        BlockStore::new(&mut self.blocks)
    }

    pub fn utxos (&mut self) -> UTXOStore {
        UTXOStore::new(&mut self.blocks)
    }

    // Batch writes to hammersbald
    pub fn batch (&mut self) -> Result<(), SPVError> {
        self.blocks.batch()?;
        Ok(self.headers_and_filters.batch()?)
    }

    /// Shutdown hammersbald
    pub fn shutdown (&mut self) {
        self.headers_and_filters.shutdown();
    }

}

fn encode_id(data: &Sha256dHash) -> Result<Vec<u8>, SPVError> {
    Ok(data.be_hex_string().as_bytes().to_vec())
}

fn decode_id(data: Vec<u8>) -> Result<Sha256dHash, SPVError> {
    use std::str::from_utf8;
    if let Ok(s) = from_utf8(data.as_slice()) {
        if let Ok (hash) = Sha256dHash::from_hex(s) {
            return Ok(hash);
        }
    }
    return Err(SPVError::Downstream("unable to decode id to a hash".to_owned()));
}
