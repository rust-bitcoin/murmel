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
//! # Store block filters
//!

use error::SPVError;

use hammersbald:: {
    PRef,
    BitcoinAdaptor
};

use bitcoin:: {
    util:: {
        hash::{Sha256dHash, BitcoinHash}
    },
    consensus::{Decodable, Encodable, encode, Encoder, Decoder}
};

/// Filter stored
#[derive(Clone)]
pub struct StoredFilter {
    /// block
    pub block_id: Sha256dHash,
    /// hash of the filter content
    pub filter_hash: Sha256dHash,
    /// previous filter id
    pub previous: Sha256dHash,
    /// filter content
    pub filter: Option<Vec<u8>>
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredFilter {
    fn bitcoin_hash(&self) -> Sha256dHash {
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&self.filter_hash.as_bytes()[..]);
        id_data[0..32].copy_from_slice(&self.previous.as_bytes()[..]);
        Sha256dHash::from_data(&id_data)
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredFilter {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.block_id.consensus_encode(s)?;
        self.filter_hash.consensus_encode(s)?;
        self.previous.consensus_encode(s)?;
        if let Some (ref filter) = self.filter {
            filter.consensus_encode(s)?;
        }
        else {
            [0u8;0].consensus_encode(s)?;
        }
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredFilter {
    fn consensus_decode(d: &mut D) -> Result<StoredFilter, encode::Error> {
        Ok(StoredFilter {
            block_id: Decodable::consensus_decode(d)?,
            filter_hash: Decodable::consensus_decode(d)?,
            previous: Decodable::consensus_decode(d)?,
            filter: {
                let f:Vec<u8> = Decodable::consensus_decode(d)?;
                if f.len () == 0 {
                    None
                }
                else {
                    Some(f)
                }
            }})
    }
}

pub struct FilterStore<'a> {
    hammersbald: &'a mut BitcoinAdaptor
}

impl<'a> FilterStore<'a> {
    pub fn new(hammersbald: &mut BitcoinAdaptor) -> FilterStore {
        FilterStore { hammersbald }
    }

    pub fn store(&mut self, filter: &StoredFilter) -> Result<PRef, SPVError> {
        Ok(self.hammersbald.put_hash_keyed(filter)?)
    }

    pub fn fetch(&self, id: &Sha256dHash) -> Result<Option<StoredFilter>, SPVError> {
        if let Some((_, stored)) = self.hammersbald.get_hash_keyed::<StoredFilter>(id)? {
            return Ok(Some(stored))
        }
        Ok(None)
    }
}

