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
    // transactions
    pub txdata: Vec<PRef>,
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredBlock {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.txdata.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock { txdata: Decodable::consensus_decode(d)? })
    }
}

pub struct BlockStore<'a> {
    hammersbald: &'a mut BitcoinAdaptor
}

const BLOCK_TIP_KEY: &[u8] = &[1u8;1];

impl<'a> BlockStore<'a> {
    pub fn new(hammersbald: &mut BitcoinAdaptor) -> BlockStore {
        BlockStore { hammersbald }
    }

    pub fn store(&mut self, block: &Block) -> Result<PRef, SPVError> {
        let mut txdata = Vec::new();
        for tx in &block.txdata {
            txdata.push(self.hammersbald.put_encodable(tx)?);
        }
        let stored = StoredBlock{txdata};
        Ok(self.hammersbald.put_keyed_encodable(block.bitcoin_hash().as_bytes(), &stored)?)
    }

    pub fn fetch(&self, id: &Sha256dHash) -> Result<Option<(PRef, StoredBlock)>, SPVError> {
        if let Some((pref, stored)) = self.hammersbald.get_keyed_decodable::<StoredBlock>(id.as_bytes())? {
            return Ok(Some((pref, stored)))
        }
        Ok(None)
    }

    pub fn store_tip(&mut self, tip: &Sha256dHash) -> Result<(), SPVError> {
        self.hammersbald.put_keyed_encodable(BLOCK_TIP_KEY, tip)?;
        Ok(())
    }

    pub fn fetch_tip(&self) -> Result<Option<Sha256dHash>, SPVError> {
        if let Some((_, h)) = self.hammersbald.get_keyed_decodable(BLOCK_TIP_KEY)? {
            return Ok(Some(h))
        }
        Ok(None)
    }
}

