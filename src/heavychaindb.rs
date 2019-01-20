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


use std::{
    path::Path,
    collections::HashMap
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

    pub fn unwind_utxo (&mut self, block_id: &Sha256dHash) -> Result<(), SPVError> {
        self.unwind(block_id)
    }

    pub fn store_block(&mut self, block: &Block) -> Result<PRef, SPVError> {
        let mut txdata = Vec::new();
        for tx in &block.txdata {
            txdata.push(self.hammersbald.put_encodable(tx)?);
        }
        let stored = StoredBlock { txdata };
        Ok(self.hammersbald.put_encodable(&stored)?)
    }

    pub fn fetch_block(&self, block_ref: PRef) -> Result<StoredBlock, SPVError> {
        let (_, stored) = self.hammersbald.get_decodable::<StoredBlock>(block_ref)?;
        Ok(stored)
    }

    pub fn apply_block(&mut self, block_ref: PRef) -> Result<(), SPVError> {
        let (block_id, block) = self.hammersbald.get_decodable::<StoredBlock>(block_ref)?;
        let block_id = Sha256dHash::from(block_id.as_slice());
        let mut new_utxos = HashMap::new();
        let mut unwinds = Vec::new();
        for (i, tx_ref) in block.txdata.iter().enumerate() {
            let (_, tx) = self.hammersbald.get_decodable::<Transaction>(*tx_ref)?;
            let tx_nr = i as u32;
            let txid = tx.txid();
            for (idx, output) in tx.output.iter().enumerate() {
                let vout = idx as u32;
                if !output.script_pubkey.is_provably_unspendable() {
                    new_utxos.insert(OutPoint { txid, vout }, (tx_nr, vout));
                }
            }
            if !tx.is_coin_base() {
                for input in tx.input {
                    if new_utxos.remove(&input.previous_output).is_none() {
                        let key = utxo_key(&input.previous_output).as_bytes().clone();
                        if let Some((pref, _)) = self.hammersbald.get_keyed(&key)? {
                            unwinds.push(pref);
                            self.hammersbald.forget(&key)?;
                        } else {
                            return Err(SPVError::UnknownUTXO);
                        }
                    }
                }
            }
        }
        for (coin, (tx_nr, vout)) in new_utxos {
            self.hammersbald.put_keyed_encodable(utxo_key(&coin).as_bytes(),
                                                 &StoredUTXO { tx_ref: block.txdata[tx_nr as usize], vout })?;
        }
        self.hammersbald.put_keyed_encodable(unwind_key(&block_id).as_bytes(), &UTXOUnwind { unwinds })?;
        Ok(())
    }

    pub fn unwind(&mut self, block_id: &Sha256dHash) -> Result<(), SPVError> {
        if let Some((_, stored_block)) = self.hammersbald.get_keyed_decodable::<StoredBlock>(block_id.as_bytes())? {
            for tx_ref in stored_block.txdata {
                let (_, tx) = self.hammersbald.get_decodable::<Transaction>(tx_ref)?;
                let txid = tx.txid();
                for vout in 0u32..tx.output.len() as u32 {
                    self.hammersbald.forget(utxo_key(&OutPoint { txid, vout }).as_bytes())?;
                }
            }
            if let Some((_, utxo_unwind)) = self.hammersbald.get_keyed_decodable::<UTXOUnwind>(unwind_key(block_id).as_bytes())? {
                for u in utxo_unwind.unwinds {
                    let su = self.hammersbald.get_decodable::<StoredUTXO>(u)?.1;
                    let tx_ref = su.tx_ref;
                    let (_, tx) = self.hammersbald.get_decodable::<Transaction>(tx_ref)?;
                    let txid = tx.txid();
                    let vout = su.vout;
                    self.hammersbald.put_keyed_encodable(utxo_key(&OutPoint { txid, vout }).as_bytes(), &su)?;
                }
            }
        }
        Ok(())
    }

    pub fn get_utxo(&self, coin: &OutPoint) -> Result<Option<(Script, u64)>, SPVError> {
        if let Some((_, utxo)) = self.hammersbald.get_keyed_decodable::<StoredUTXO>(utxo_key(coin).as_bytes())? {
            let tx_ref = utxo.tx_ref;
            let (_, tx) = self.hammersbald.get_decodable::<Transaction>(tx_ref)?;
            let output = tx.output[utxo.vout as usize].clone();
            return Ok(Some((output.script_pubkey, output.value)));
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

pub struct StoredUTXO {
    tx_ref: PRef,
    vout: u32,
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredUTXO {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.tx_ref.as_u64().consensus_encode(s)?;
        self.vout.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredUTXO {
    fn consensus_decode(d: &mut D) -> Result<StoredUTXO, encode::Error> {
        Ok(StoredUTXO {
            tx_ref: Decodable::consensus_decode(d)?,
            vout: Decodable::consensus_decode(d)?,
        })
    }
}

fn utxo_key(coin: &OutPoint) -> Sha256dHash {
    let mut buf = vec!();
    coin.consensus_encode(&mut buf).unwrap();
    Sha256dHash::from_data(buf.as_slice())
}

pub struct UTXOUnwind {
    unwinds: Vec<PRef>
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

fn unwind_key(block_id: &Sha256dHash) -> Sha256dHash {
    // rehash again for unique linked id
    Sha256dHash::from_data(block_id.as_bytes())
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
