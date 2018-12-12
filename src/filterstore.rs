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
    api::{HammersbaldAPI, Hammersbald},
    pref::PRef,
    error::HammersbaldError
};

use bitcoin:: {
    blockdata::{
        block::{Block},
        transaction::Transaction
    },
    util:: {
        hash::{Sha256dHash, BitcoinHash}
    },
    consensus::{Decodable, Encodable}
};

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use std:: {
    io::Cursor
};

/// Block stored
pub struct StoredBlock {
    /// Bitcoin block
    pub block: Block,
    /// filter id (BIP158)
    pub filter_id: Sha256dHash
}

/// Adapter for Hammersbald storing Bitcoin data
pub struct FilterStore {
    hammersbald: Hammersbald
}

impl FilterStore {
    /// create a new Bitcoin adapter wrapping Hammersbald
    pub fn new(hammersbald: Hammersbald) -> FilterStore {
        FilterStore { hammersbald }
    }

    pub fn insert_filter(&mut self, previous_filter: &Sha256dHash, filter: Vec<u8>) -> Result<Sha256dHash, SPVError> {
        let filter_header = Sha256dHash::from_data(filter.as_slice());
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&filter_header.as_bytes()[..]);
        id_data[0..32].copy_from_slice(&previous_filter.as_bytes()[..]);
        let filter_id = Sha256dHash::from_data(&id_data);
        self.hammersbald.put(&filter_id.as_bytes()[..], filter.as_slice(), &vec!())?;
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

        let mut referred = vec!();
        let key = &block.bitcoin_hash().to_bytes()[..];
        let mut serialized_block = Vec::new();
        serialized_block.extend(encode(&block.header)?);
        let mut tx_prefs = Vec::new();
        for t in &block.txdata {
            let pref = self.hammersbald.put_referred(encode(t)?.as_slice(), &vec!())?;
            tx_prefs.push(pref);
            referred.push(pref);
        }
        let stored_tx_offsets = self.hammersbald.put_referred(&[], &tx_prefs)?;
        referred.push(stored_tx_offsets);
        serialized_block.write_u48::<BigEndian>(stored_tx_offsets.as_u64())?;
        let filter_id = self.insert_filter(&prev_filter, filter)?;
        serialized_block.extend(filter_id.as_bytes().iter());

        Ok(self.hammersbald.put(&key[..], serialized_block.as_slice(), &referred)?)
    }

    /// Fetch a block by its id
    pub fn fetch_block (&self, id: &Sha256dHash)  -> Result<Option<StoredBlock>, SPVError> {
        let key = &id.as_bytes()[..];
        if let Some((_, stored, _)) = self.hammersbald.get(&key)? {
            let header = decode(&stored[0..80])?;
            let mut data = Cursor::new(&stored[80..]);
            let txdata_offset = PRef::from(data.read_u48::<BigEndian>()?);
            let filter_id = Sha256dHash::from (&data.into_inner()[86..86+32]);

            let mut txdata: Vec<Transaction> = Vec::new();
            if txdata_offset.is_valid() {
                let (_, _, txrefs) = self.hammersbald.get_referred(txdata_offset)?;
                for txref in &txrefs {
                    let (_, tx, _) = self.hammersbald.get_referred(*txref)?;
                    txdata.push(decode(tx.as_slice())?);
                }
            }

            return Ok(Some(StoredBlock{ block: Block { header, txdata }, filter_id}))
        }
        Ok(None)
    }
    pub fn init(&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.init()
    }

    pub fn batch(&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.batch()
    }

    pub fn shutdown(&mut self) {
        self.hammersbald.shutdown()
    }
}

fn decode<'d, T: ? Sized>(data: &'d [u8]) -> Result<T, SPVError>
    where T: Decodable<Cursor<&'d [u8]>> {
    let mut decoder  = Cursor::new(data);
    Decodable::consensus_decode(&mut decoder).map_err(|e| { SPVError::Serialize(e) })
}

fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, SPVError>
    where T: Encodable<Vec<u8>> {
    let mut result = vec!();
    data.consensus_encode(&mut result).map_err(|e| { SPVError::Serialize(e) })?;
    Ok(result)
}
