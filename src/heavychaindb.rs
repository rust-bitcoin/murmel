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


use error::SPVError;

use bitcoin::{
    BitcoinHash,
    blockdata::{
        transaction::{Transaction, OutPoint},
        block::Block,
        script::Script,
    },
    util::hash::Sha256dHash,
    consensus::{Decodable, Encodable, encode, Encoder, Decoder}
};

use hammersbald::{
    PRef,
    persistent,
    transient,
    BitcoinAdaptor,
    HammersbaldAPI
};

use byteorder::{BigEndian, ByteOrder};

use std::{
    path::Path,
    collections::{HashMap, HashSet}
};

pub struct HeavyChainDB {
    hammersbald: BitcoinAdaptor
}

impl HeavyChainDB {
    /// Create an in-memory database instance
    pub fn mem() -> Result<HeavyChainDB, SPVError> {
        info!("working with memory database");
        let blocks = BitcoinAdaptor::new(transient( 2)?);
        Ok(HeavyChainDB { hammersbald: blocks })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path) -> Result<HeavyChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let blocks = BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 100, 100)?);
        let db = HeavyChainDB { hammersbald: blocks };
        info!("heavy block database {:?} opened", path);
        Ok(db)
    }

    pub fn store_block(&mut self, height: u32, block: &Block) -> Result<PRef, SPVError> {
        let mut key = [0u8; 4];
        BigEndian::write_u32(&mut key, height);
        Ok(self.hammersbald.put_keyed_encodable(&key,&StoredBlock { height, txdata: block.txdata.clone() })?)
    }

    pub fn fetch_block(&self, height: u32) -> Result<Option<StoredBlock>, SPVError> {
        let mut key = [0u8; 4];
        BigEndian::write_u32(&mut key, height);
        if let Some((_, stored)) = self.hammersbald.get_keyed_decodable::<StoredBlock>(&key)? {
            return Ok(Some(stored));
        }
        Ok(None)
    }

    pub fn utxo_block(&mut self, block_ref: PRef) -> Result<(), SPVError> {
        let (block_id, block) = self.hammersbald.get_decodable::<StoredBlock>(block_ref)?;
        let block_id = Sha256dHash::from(block_id.as_slice());
        let mut new_utxos = HashMap::new();
        let mut unwinds = Vec::new();
        for (i, tx) in block.txdata.iter().enumerate() {
            let tx_nr = i as u32;
            let txid = tx.txid();
            for (idx, output) in tx.output.iter().enumerate() {
                let vout = idx as u32;
                if !output.script_pubkey.is_provably_unspendable() {
                    let utxo = StoredUTXO::new(block.height, tx_nr, vout);
                    new_utxos.insert(OutPoint { txid, vout }, utxo);
                }
            }
            if !tx.is_coin_base() {
                for input in &tx.input {
                    if new_utxos.remove(&input.previous_output).is_none() {
                        let ukey = utxo_key(&input.previous_output).to_bytes();
                        if let Some((_, utxo)) = self.hammersbald.get_keyed_decodable::<StoredUTXO>(&ukey)? {
                            unwinds.push(utxo);
                            self.hammersbald.forget(&ukey)?;
                        }
                        else {
                            return Err(SPVError::UnknownUTXO);
                        }
                    }
                }
            }
        }
        for (coin, utxo) in &new_utxos {
            self.hammersbald.put_keyed_encodable(utxo_key(coin).as_bytes(), utxo)?;
        }
        self.hammersbald.put_keyed_encodable(&unwind_key(block.height), &UTXOUnwind { unwinds })?;
        Ok(())
    }

    pub fn unwind_utxo(&mut self, height: u32) -> Result<(), SPVError> {
        if let Some(stored_block) = self.fetch_block(height)? {
            if let Some((_, utxo_unwind)) = self.hammersbald.get_keyed_decodable::<UTXOUnwind>(&unwind_key(height))? {
                let mut unwinds = utxo_unwind.unwinds.iter();
                let mut same_block_out = HashSet::new();
                for tx in &stored_block.txdata {
                    let txid = tx.txid();
                    for vout in 0u32..tx.output.len() as u32 {
                        let coin = OutPoint { txid, vout };
                        self.hammersbald.forget(utxo_key(&coin).as_bytes())?;
                        same_block_out.insert(coin);
                    }
                    if !tx.is_coin_base() {
                        for input in &tx.input {
                            if same_block_out.remove(&input.previous_output) == false {
                                let unwind = unwinds.next().expect(format!("corrupted db: incorrect number of unwinds for block {}", height).as_str());
                                self.hammersbald.put_keyed_encodable(&utxo_key(&input.previous_output).as_bytes()[..], unwind)?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_utxo(&self, coin: &OutPoint) -> Result<Option<(Script, u64)>, SPVError> {
        if let Some((_, utxo)) = self.hammersbald.get_keyed_decodable::<StoredUTXO>(utxo_key(coin).as_bytes())? {
            if let Some(block) = self.fetch_block(utxo.height())? {
                let tx_nr = utxo.tx_nr() as usize;
                if tx_nr < block.txdata.len () {
                    let ref tx = block.txdata[tx_nr];
                    let vout = utxo.vout() as usize;
                    if vout < tx.output.len () {
                        let ref out = tx.output[vout];
                        return Ok(Some((out.script_pubkey.clone(), out.value)));
                    }
                }
            }
        }
        debug!("no utxo for {}", coin);
        Ok(None)
    }

    // Batch writes to hammersbald
    pub fn batch (&mut self) -> Result<(), SPVError> {
        Ok(self.hammersbald.batch()?)
    }

    /// Shutdown hammersbald
    #[allow(unused)]
    pub fn shutdown (&mut self) {
        self.hammersbald.shutdown();
    }
}

/// Block stored
pub struct StoredBlock {
    // block height
    pub height: u32,
    // transactions
    pub txdata: Vec<Transaction>,
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredBlock {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.height.consensus_encode(s)?;
        self.txdata.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock { height: Decodable::consensus_decode(d)?, txdata: Decodable::consensus_decode(d)? })
    }
}

pub struct StoredUTXO {
    utxo_id: u64
}

impl StoredUTXO {
    pub fn new (height: u32, tx_nr: u32, vout: u32) -> StoredUTXO {
        StoredUTXO { utxo_id: (height as u64) << 39 | (tx_nr as u64) << 15 | (vout as u64) }
    }

    pub fn height(&self) -> u32 {
        (self.utxo_id >> 39) as u32
    }

    pub fn tx_nr(&self) -> u32 {
        ((self.utxo_id >> 15) & 0xffffff) as u32
    }

    pub fn vout (&self) -> u32 {
        (self.utxo_id & 0xffff) as u32
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredUTXO {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.utxo_id.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredUTXO {
    fn consensus_decode(d: &mut D) -> Result<StoredUTXO, encode::Error> {
        Ok(StoredUTXO {
            utxo_id: Decodable::consensus_decode(d)?
        })
    }
}

fn utxo_key(coin: &OutPoint) -> Sha256dHash {
    let mut buf = vec!();
    coin.consensus_encode(&mut buf).unwrap();
    Sha256dHash::from_data(buf.as_slice())
}

pub struct UTXOUnwind {
    unwinds: Vec<StoredUTXO>
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for UTXOUnwind {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.unwinds.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for UTXOUnwind {
    fn consensus_decode(d: &mut D) -> Result<UTXOUnwind, encode::Error> {
        Ok(UTXOUnwind {
            unwinds: Decodable::consensus_decode(d)?
        })
    }
}

fn unwind_key(height: u32) -> [u8; 5] {
    let mut key = [0u8; 5];
    BigEndian::write_u32(&mut key[1..5], height);
    key
}

pub struct DBUTXOAccessor<'a> {
    utxostore: &'a HeavyChainDB,
    same_block_utxo: HashMap<(Sha256dHash, u32), (Script, u64)>,
}

impl<'a> DBUTXOAccessor<'a> {
    pub fn new(utxostore: &'a HeavyChainDB, block: &Block) -> Result<DBUTXOAccessor<'a>, SPVError> {
        let mut acc = DBUTXOAccessor { utxostore: utxostore, same_block_utxo: HashMap::new() };
        for t in &block.txdata {
            let id = t.txid();
            for (ix, o) in t.output.iter().enumerate() {
                acc.same_block_utxo.insert((id, ix as u32), (o.script_pubkey.clone(), o.value));
            }
        }
        Ok(acc)
    }
}


pub trait UTXOAccessor {
    fn get_utxo(&self, coin: &OutPoint) -> Result<Option<(Script, u64)>, SPVError>;
}

impl<'a> UTXOAccessor for DBUTXOAccessor<'a> {
    fn get_utxo(&self, coin: &OutPoint) -> Result<Option<(Script, u64)>, SPVError> {
        if let Some(r) = self.same_block_utxo.get(&(coin.txid, coin.vout)) {
            return Ok(Some(r.clone()));
        }
        self.utxostore.get_utxo(coin)
    }
}
