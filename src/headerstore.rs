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
//! # Store headers
//!

use bitcoin:: {
    BitcoinHash,
    blockdata::{
        block::{BlockHeader}
    },
    consensus::{Decodable, Encodable},
    util:: {
        hash::Sha256dHash
    },
    consensus::{
        encode,
        encode::{Encoder, Decoder}
    }
};

use error::SPVError;
use hammersbald:: {
    PRef,
    BitcoinAdaptor
};
use std:: {
    error::Error
};

use byteorder::{BigEndian, ByteOrder};

pub struct HeaderStore<'a> {
    hammersbald: &'a mut BitcoinAdaptor
}

/// A header enriched with information about its position on the blockchain
#[derive(Clone)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub log2work: f32
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.header.bitcoin_hash()
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredHeader {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.header.consensus_encode(s)?;
        self.height.consensus_encode(s)?;
        let mut buf = [0u8;4];
        BigEndian::write_f32(&mut buf, self.log2work);
        buf.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredHeader {
    fn consensus_decode(d: &mut D) -> Result<StoredHeader, encode::Error> {
        let buf :[u8; 4] = Decodable::consensus_decode(d)?;
        Ok(StoredHeader {
            header: Decodable::consensus_decode(d)?,
            height: Decodable::consensus_decode(d)?,
            log2work: BigEndian::read_f32(&buf) })
    }
}

const HEADER_TIP_KEY: &[u8] = &[0u8;1];

impl<'a> HeaderStore<'a> {
    pub fn new(hammersbald: &mut BitcoinAdaptor) -> HeaderStore {
        HeaderStore { hammersbald }
    }

    pub fn store(&mut self, stored: &StoredHeader) -> Result<PRef, SPVError> {
        Ok(self.hammersbald.put_hash_keyed(stored)?)
    }

    pub fn store_tip(&mut self, tip: &Sha256dHash) -> Result<(), SPVError> {
        self.hammersbald.put_keyed_encodable(HEADER_TIP_KEY, tip)?;
        Ok(())
    }

    pub fn fetch_tip(&self) -> Result<Option<Sha256dHash>, SPVError> {
        if let Some((_, h)) = self.hammersbald.get_keyed_decodable(HEADER_TIP_KEY)? {
            return Ok(Some(h))
        }
        Ok(None)
    }

    pub fn fetch(&self, id: &Sha256dHash) -> Result<Option<StoredHeader>, Box<Error>> {
        if let Some((_,stored)) = self.hammersbald.get_hash_keyed::<StoredHeader>(id)? {
            return Ok(Some(stored));
        }
        Ok(None)
    }
}
