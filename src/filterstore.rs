//
// Copyright 2018 Tamas Blummer
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
    HammersbaldAPI,
    PRef,
    HammersbaldError,
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

use std:: {
    io::Cursor,
    error::Error
};

/// Block stored
pub struct StoredBlock {
    /// Bitcoin block
    pub block: Block,
    /// filter id (BIP158)
    pub filter_id: Sha256dHash
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
        self.filter_id.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock {
            block: Decodable::consensus_decode(d)?,
            filter_id: Decodable::consensus_decode(d)?})
    }
}

/// Filter stored
pub struct StoredFilter {
    /// filter id
    pub id: Sha256dHash,
    /// previous filter id
    pub previous: Sha256dHash,
    /// filter content
    pub filter: Vec<u8>
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredFilter {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.id
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredFilter {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.id.consensus_encode(s)?;
        self.previous.consensus_encode(s)?;
        self.filter.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredFilter {
    fn consensus_decode(d: &mut D) -> Result<StoredFilter, encode::Error> {
        Ok(StoredFilter {
            id: Decodable::consensus_decode(d)?,
            previous: Decodable::consensus_decode(d)?,
            filter: Decodable::consensus_decode(d)?})
    }
}

/// Adapter for Hammersbald storing Bitcoin data
pub struct FilterStore {
    hammersbald: BitcoinAdaptor
}

impl FilterStore {
    /// create a new Bitcoin adapter wrapping Hammersbald
    pub fn new(hammersbald: Box<HammersbaldAPI>) -> FilterStore {
        FilterStore { hammersbald: BitcoinAdaptor::new(hammersbald) }
    }

    pub fn insert_filter(&mut self, previous_filter: &Sha256dHash, filter: Vec<u8>) -> Result<Sha256dHash, SPVError> {
        let filter_header = Sha256dHash::from_data(filter.as_slice());
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&filter_header.as_bytes()[..]);
        id_data[0..32].copy_from_slice(&previous_filter.as_bytes()[..]);
        let filter_id = Sha256dHash::from_data(&id_data);
        let stored = StoredFilter{id: filter_id, previous: previous_filter.clone(), filter };
        self.hammersbald.put_hash_keyed(&stored)?;
        Ok(filter_id)
    }

    /// insert a block
    pub fn insert_block(&mut self, block: &Block, filter: Vec<u8>) -> Result<PRef, SPVError> {

        let prev_filter;
        if let Some(prev) = self.fetch_block(&block.header.prev_blockhash)? {
            prev_filter = prev.filter_id;
        }
        else {
            prev_filter = Sha256dHash::default();
        }
        let filter_id = self.insert_filter(&prev_filter, filter)?;
        let stored = StoredBlock{block: block.clone(), filter_id};
        Ok(self.hammersbald.put_hash_keyed(&stored)?)
    }

    /// Fetch a block by its id
    pub fn fetch_block (&self, id: &Sha256dHash)  -> Result<Option<StoredBlock>, SPVError> {
        if let Some((_, stored)) = self.hammersbald.get_hash_keyed::<StoredBlock>(id)? {
            return Ok(Some(stored))
        }
        Ok(None)
    }

    pub fn batch(&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.batch()
    }
}

