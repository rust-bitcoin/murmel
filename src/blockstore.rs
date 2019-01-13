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
//! # store blocks
//!

use error::SPVError;

use hammersbald:: {
    PRef,
    BitcoinAdaptor
};

use bitcoin:: {
    blockdata::{
        block::{Block}
    },
    util:: {
        hash::{Sha256dHash, BitcoinHash}
    },
    consensus::{Decodable, Encodable, encode, Encoder, Decoder}
};

/// Block stored
pub struct StoredBlock {
    /// Bitcoin block
    pub block: Block,
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredBlock {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.block.bitcoin_hash()
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredBlock {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.block.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock { block: Decodable::consensus_decode(d)? })
    }
}

pub struct BlockStore<'a> {
    hammersbald: &'a mut BitcoinAdaptor
}

impl<'a> BlockStore<'a> {
    pub fn new(hammersbald: &mut BitcoinAdaptor) -> BlockStore {
        BlockStore { hammersbald }
    }

    pub fn store_block(&mut self, block: &Block) -> Result<PRef, SPVError> {
        let stored = StoredBlock{block: block.clone()};
        Ok(self.hammersbald.put_hash_keyed(&stored)?)
    }

    pub fn fetch_block (&self, id: &Sha256dHash)  -> Result<Option<StoredBlock>, SPVError> {
        if let Some((_, stored)) = self.hammersbald.get_hash_keyed::<StoredBlock>(id)? {
            return Ok(Some(stored))
        }
        Ok(None)
    }
}

