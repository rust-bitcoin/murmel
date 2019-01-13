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
    BitcoinAdaptor
};

use bitcoin:: {
    util:: {
        hash::{Sha256dHash, BitcoinHash}
    },
    consensus::{Decodable, Encodable, encode, Encoder, Decoder}
};

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

pub struct FilterStore<'a> {
    hammersbald: &'a mut BitcoinAdaptor
}

impl<'a> FilterStore<'a> {
    pub fn new(hammersbald: &mut BitcoinAdaptor) -> FilterStore {
        FilterStore { hammersbald }
    }

    pub fn store_filter(&mut self, previous_filter: &Sha256dHash, filter: Vec<u8>) -> Result<StoredFilter, SPVError> {
        let filter_header = Sha256dHash::from_data(filter.as_slice());
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&filter_header.as_bytes()[..]);
        id_data[0..32].copy_from_slice(&previous_filter.as_bytes()[..]);
        let filter_id = Sha256dHash::from_data(&id_data);
        let stored = StoredFilter{id: filter_id, previous: previous_filter.clone(), filter };
        self.hammersbald.put_hash_keyed(&stored)?;
        Ok(stored)
    }

    pub fn fetch_filter(&self, id: &Sha256dHash) -> Result<Option<StoredFilter>, SPVError> {
        if let Some((_, stored)) = self.hammersbald.get_hash_keyed::<StoredFilter>(id)? {
            return Ok(Some(stored))
        }
        Ok(None)
    }
}

