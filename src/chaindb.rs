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
//! # Blockchain DB for a node
//!

use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::{Block, BlockHeader},
        constants::genesis_block,
        script::Script,
        transaction::{OutPoint, Transaction},
    },
    consensus::{Decodable, Decoder, Encodable, encode, Encoder},
    network::constants::Network,
    util::hash::Sha256dHash,
};

use byteorder::{BigEndian, ByteOrder};
use error::SPVError;
use filtercache::FilterCache;
use hammersbald::{
    BitcoinAdaptor, HammersbaldAPI, persistent, PRef,
    transient,
};
use headercache::{HeaderCache, HeaderIterator, TrunkIterator};

use lru_cache::LruCache;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, RwLock, Mutex},
};
use std::{
    path::Path
};

pub type SharedChainDB = Arc<RwLock<ChainDB>>;

pub struct ChainDB {
    light: BitcoinAdaptor,
    heavy: Option<BitcoinAdaptor>,
    headercache: HeaderCache,
    filtercache: FilterCache,
    utxocache: Mutex<LruCache<u64, Script>>,
    network: Network,
}

const UTXO_CACHE_SIZE:usize = 1024*1024;

impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network, heavy: bool) -> Result<ChainDB, SPVError> {
        info!("working with in memory chain db");
        let light = BitcoinAdaptor::new(transient(2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        let utxocache = Mutex::new(LruCache::new(UTXO_CACHE_SIZE));
        if heavy {
            let heavy = Some(BitcoinAdaptor::new(transient(2)?));
            Ok(ChainDB { light, heavy, network, headercache, filtercache, utxocache })
        } else {
            Ok(ChainDB { light, heavy: None, network, headercache, filtercache, utxocache })
        }
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network, heavy: bool) -> Result<ChainDB, SPVError> {
        let basename = path.to_str().unwrap().to_string();
        let light = BitcoinAdaptor::new(persistent((basename.clone() + ".h").as_str(), 100, 2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        let utxocache = Mutex::new(LruCache::new(UTXO_CACHE_SIZE));
        if heavy {
            let heavy = Some(BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 1000, 100)?));
            Ok(ChainDB { light, heavy, network, headercache, filtercache, utxocache })
        } else {
            Ok(ChainDB { light, heavy: None, network, headercache, filtercache, utxocache })
        }
    }

    pub fn init(&mut self) -> Result<(), SPVError> {
        self.init_headers()?;
        // TODO read filters
        Ok(())
    }

    pub fn batch(&mut self) -> Result<(), SPVError> {
        self.light.batch()?;
        if let Some(ref mut heavy) = self.heavy {
            heavy.batch()?;
        }
        Ok(())
    }

    fn init_headers(&mut self) -> Result<(), SPVError> {
        let mut sl = VecDeque::new();
        {
            if let Some(tip) = self.fetch_header_tip()? {
                info!("reading stored header chain from tip {}", tip);
                let mut h = tip;
                while let Some(stored) = self.fetch_header(&h)? {
                    sl.push_front(stored.clone());
                    if stored.header.prev_blockhash != Sha256dHash::default() {
                        h = stored.header.prev_blockhash;
                    } else {
                        break;
                    }
                }
                info!("read {} headers", sl.len());
            }
        }

        if sl.is_empty() {
            info!("Initialized with genesis header.");
            let genesis = genesis_block(self.network).header;
            if let Some((stored, _, _)) = self.headercache.add_header(&genesis)? {
                self.store_header(&stored)?;
                self.store_header_tip(&stored.bitcoin_hash())?;
            }
        } else {
            self.headercache.clear();
            while let Some(stored) = sl.pop_front() {
                self.headercache.add_header_unchecked(&stored);
                if let Some(filter_ref) = stored.filter {
                    let filter = self.fetch_filter(filter_ref)?;
                    self.filtercache.add_filter(&filter);
                }
            }
            info!("read {} filter header", self.filtercache.len());
        }
        Ok(())
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, SPVError> {
        if let Some((stored, unwinds, forward)) = self.headercache.add_header(header)? {
            self.store_header(&stored)?;
            if let Some(forward) = forward.clone() {
                if forward.len() > 0 {
                    self.store_header_tip(forward.last().unwrap())?;
                }
            }
            return Ok(Some((stored, unwinds, forward)));
        }
        Ok(None)
    }

    pub fn update_header_with_block(&mut self, id: &Sha256dHash, block_ref: PRef) -> Result<Option<PRef>, SPVError> {
        if let Some(stored) = self.headercache.update_header_with_block(id, block_ref) {
            return Ok(Some(self.store_header(&stored)?));
        }
        Ok(None)
    }


    pub fn update_header_with_filter(&mut self, id: &Sha256dHash, filter_ref: PRef) -> Result<Option<PRef>, SPVError> {
        if let Some(stored) = self.headercache.update_header_with_filter(id, filter_ref) {
            return Ok(Some(self.store_header(&stored)?));
        }
        Ok(None)
    }

    pub fn iter_to_genesis<'a>(&'a self, id: &Sha256dHash) -> HeaderIterator<'a> {
        return self.headercache.iter_to_genesis(id);
    }

    pub fn iter_trunk_to_genesis<'a>(&'a self) -> HeaderIterator<'a> {
        return self.headercache.iter_trunk_to_genesis();
    }

    pub fn iter_to_tip<'a>(&'a self, id: &Sha256dHash) -> TrunkIterator<'a> {
        return self.headercache.iter_to_tip(id);
    }

    /// is the given hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        self.headercache.is_on_trunk(hash)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<StoredHeader> {
        self.headercache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        self.headercache.get_header(id)
    }

    // locator for getheaders message
    pub fn header_locators(&self) -> Vec<Sha256dHash> {
        self.headercache.locator_hashes()
    }

    pub fn get_block_filter (&self, block_id: &Sha256dHash) -> Option<StoredFilter> {
        self.filtercache.get_block_filter(block_id)
    }

    pub fn add_filter_chain(&mut self, prev_block_id: &Sha256dHash, prev_filter_id: &Sha256dHash, filter_hashes: impl Iterator<Item=Sha256dHash>) ->
    Result<Option<(Sha256dHash, Sha256dHash)>, SPVError> {
        if let Some(prev_filter) = self.filtercache.get_block_filter(prev_filter_id) {
            if prev_filter.block_id == *prev_block_id {
                let mut previous = *prev_filter_id;
                let mut p_block = *prev_block_id;
                let mut filters = Vec::new();
                for (block_id, filter_hash) in self.headercache.iter_to_tip(prev_block_id).zip(filter_hashes) {
                    let mut buf = [0u8; 64];
                    buf[0..32].copy_from_slice(&filter_hash.to_bytes()[..]);
                    buf[32..].copy_from_slice(&previous.to_bytes()[..]);
                    let filter_id = Sha256dHash::from_data(&buf);
                    previous = filter_id;
                    p_block = block_id;
                    let filter = StoredFilter { block_id, previous, filter_hash, filter: None };
                    filters.push(filter);
                }
                for filter in filters {
                    self.store_filter(&filter)?;
                    self.filtercache.add_filter(&filter);
                }
                return Ok(Some((p_block, previous)));
            }
        }
        Ok(None)
    }

    // update if matching stored filter_header chain
    pub fn update_filter(&mut self, block_id: &Sha256dHash, filter: Vec<u8>) -> Result<bool, SPVError> {
        if let Some(filter_header) = self.filtercache.get_block_filter(block_id) {
            let filter_hash = Sha256dHash::from_data(filter.as_slice());
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(&filter_hash.to_bytes()[..]);
            buf[32..].copy_from_slice(&filter_header.previous.to_bytes()[..]);
            let filter_id = Sha256dHash::from_data(&buf);
            if filter_id == filter_header.bitcoin_hash() {
                let stored = StoredFilter {
                    block_id: *block_id,
                    previous: filter_header.previous,
                    filter_hash,
                    filter: Some(filter),
                };
                self.store_filter(&stored)?;
                self.filtercache.add_filter(&stored);
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn store_header(&mut self, stored: &StoredHeader) -> Result<PRef, SPVError> {
        Ok(self.light.put_hash_keyed(stored)?)
    }

    pub fn store_header_tip(&mut self, tip: &Sha256dHash) -> Result<(), SPVError> {
        self.light.put_keyed_encodable(HEADER_TIP_KEY, tip)?;
        Ok(())
    }

    pub fn fetch_header_tip(&self) -> Result<Option<Sha256dHash>, SPVError> {
        if let Some((_, h)) = self.light.get_keyed_decodable(HEADER_TIP_KEY)? {
            return Ok(Some(h));
        }
        Ok(None)
    }

    pub fn fetch_header(&self, id: &Sha256dHash) -> Result<Option<StoredHeader>, SPVError> {
        if let Some((_, stored)) = self.light.get_hash_keyed::<StoredHeader>(id)? {
            return Ok(Some(stored));
        }
        Ok(None)
    }

    pub fn store_filter(&mut self, filter: &StoredFilter) -> Result<PRef, SPVError> {
        Ok(self.light.put_hash_keyed(filter)?)
    }


    pub fn fetch_filter(&self, pref: PRef) -> Result<StoredFilter, SPVError> {
        let (_, stored) = self.light.get_decodable::<StoredFilter>(pref)?;
        return Ok(stored);
    }

    pub fn store_known_filter (&mut self, block_id: &Sha256dHash, previous_filter: &Sha256dHash, content: Vec<u8>) -> Result<Sha256dHash, SPVError> {
        let stored = StoredFilter{block_id: block_id.clone(), previous: previous_filter.clone(),
            filter_hash: Sha256dHash::from_data(content.as_slice()), filter: Some(content) };
        let pref = self.store_filter(&stored)?;
        self.filtercache.add_filter(&stored);
        self.update_header_with_filter(block_id, pref)?;
        Ok(stored.bitcoin_hash())
    }

    pub fn store_block(&mut self, block: &Block) -> Result<PRef, SPVError> {
        if let Some(header) = self.headercache.get_header(&block.bitcoin_hash()) {
            let pref;
            if let Some(ref mut heavy) = self.heavy {
                let height = header.height;
                let mut key = [0u8; 4];
                BigEndian::write_u32(&mut key, height);
                pref = heavy.put_keyed_encodable(&key, &StoredBlock { id: block.bitcoin_hash(), height, txdata: block.txdata.clone() })?;
            } else {
                panic!("Configuration error. No db to store block.");
            }
            self.update_header_with_block(&block.bitcoin_hash(), pref)?;
            return Ok(pref);
        }
        panic!("should not call store block before header is known {}", block.bitcoin_hash());
    }

    pub fn fetch_block(&self, height: u32) -> Result<Option<StoredBlock>, SPVError> {
        if let Some(ref heavy) = self.heavy {
            let mut key = [0u8; 4];
            BigEndian::write_u32(&mut key, height);
            if let Some((_, stored)) = heavy.get_keyed_decodable::<StoredBlock>(&key)? {
                return Ok(Some(stored));
            }
            else {
                return Ok(None);
            }
        }
        panic!("Configuration error. No db to fetch block.");
    }

    pub fn utxo_tip (&self) -> Result<Option<Sha256dHash>, SPVError> {
        if let Some(ref heavy) = self.heavy {
            if let Some((_, tip)) = heavy.get_keyed_decodable::<Sha256dHash>(UTXO_TIP)? {
                return Ok(Some(tip));
            }
            return Ok(None);
        }
        panic!("Configuration error. No db to fetch utxo tip.");
    }

    pub fn utxo_block(&mut self, block_ref: PRef) -> Result<(), SPVError> {
        if let Some(ref mut heavy) = self.heavy {
            let (_, block) = heavy.get_decodable::<StoredBlock>(block_ref)?;
            if let Some((_, tip)) = heavy.get_keyed_decodable::<Sha256dHash>(UTXO_TIP)? {
                if tip == block.id {
                    warn!("utxo calculation for same block");
                    return Ok(());
                }
                if let Some(header) = self.headercache.get_header(&block.id) {
                    if tip != header.header.prev_blockhash {
                        error!("attempt to apply the wrong block {} to utxo {}", block.id, tip);
                        return Err(SPVError::UnknownUTXO);
                    }
                }
                else {
                    error!("header unknown for utxo block");
                    return Err(SPVError::UnknownUTXO);
                }
            }
            let mut new_utxos = HashMap::new();
            let mut unwinds = Vec::new();
            for (i, tx) in block.txdata.iter().enumerate() {
                let tx_nr = i as u32;
                let txid = tx.txid();
                for (idx, output) in tx.output.iter().enumerate() {
                    let vout = idx as u32;
                    if !output.script_pubkey.is_provably_unspendable() {
                        let utxo = StoredUTXO::new(block.height, tx_nr, vout);
                        new_utxos.insert(OutPoint { txid, vout }, (utxo, output.script_pubkey.clone()));
                    }
                }
                if !tx.is_coin_base() {
                    for input in &tx.input {
                        if new_utxos.remove(&input.previous_output).is_none() {
                            let ukey = utxo_key(&input.previous_output).to_bytes();
                            if let Some((_, utxo)) = heavy.get_keyed_decodable::<StoredUTXO>(&ukey)? {
                                unwinds.push(utxo);
                                heavy.forget(&ukey)?;
                            } else {
                                return Err(SPVError::UnknownUTXO);
                            }
                        }
                    }
                }
            }
            let mut utxocache = self.utxocache.lock().unwrap();
            for (coin, (utxo, script)) in &new_utxos {
                heavy.put_keyed_encodable(utxo_key(coin).as_bytes(), utxo)?;
                utxocache.insert(utxo.utxo_id, script.clone());
            }
            heavy.put_keyed_encodable(&unwind_key(&block.id).as_bytes()[..], &UTXOUnwind { unwinds })?;
            heavy.put_keyed_encodable(UTXO_TIP, &block.id)?;
            return Ok(());
        }
        panic!("Configuration error. No db to store utxo.");
    }

    pub fn unwind_utxo(&mut self, id: &Sha256dHash) -> Result<Sha256dHash, SPVError> {
        self.utxocache.lock().unwrap().clear();
        if let Some(header) = self.headercache.get_header(id) {
            let height = header.height;
            if let Some(stored_block) = self.fetch_block(height)? {
                if let Some(ref mut heavy) = self.heavy {
                    if let Some((_, utxo_unwind)) = heavy.get_keyed_decodable::<UTXOUnwind>(&unwind_key(&stored_block.id).as_bytes()[..])? {
                        let mut unwinds = utxo_unwind.unwinds.iter();
                        let mut same_block_out = HashSet::new();
                        for tx in &stored_block.txdata {
                            let txid = tx.txid();
                            for vout in 0u32..tx.output.len() as u32 {
                                let coin = OutPoint { txid, vout };
                                heavy.forget(utxo_key(&coin).as_bytes())?;
                                same_block_out.insert(coin);
                            }
                            if !tx.is_coin_base() {
                                for input in &tx.input {
                                    if same_block_out.remove(&input.previous_output) == false {
                                        let unwind = unwinds.next().expect(format!("corrupted db: incorrect number of unwinds for block {}", height).as_str());
                                        heavy.put_keyed_encodable(&utxo_key(&input.previous_output).as_bytes()[..], unwind)?;
                                    }
                                }
                            }
                        }
                        return Ok(header.header.prev_blockhash);
                    }
                }
                else {
                    panic!("Configuration error. No db to unwind utxo.");
                }
            }
        }
        error!("attempt to unwind the wrong block");
        Err(SPVError::UnknownUTXO)
    }

    pub fn get_utxo(&self, coin: &OutPoint) -> Result<Option<Script>, SPVError> {
        if let Some(ref heavy) = self.heavy {
            if let Some((_, utxo)) = heavy.get_keyed_decodable::<StoredUTXO>(utxo_key(coin).as_bytes())? {
                {
                    let mut utxocache = self.utxocache.lock().unwrap();
                    if let Some(script) = utxocache.get_mut(&utxo.utxo_id) {
                        return Ok(Some(script.clone()));
                    }
                }
                if let Some(block) = self.fetch_block(utxo.height())? {
                    let tx_nr = utxo.tx_nr() as usize;
                    if tx_nr < block.txdata.len() {
                        let ref tx = block.txdata[tx_nr];
                        let vout = utxo.vout() as usize;
                        if vout < tx.output.len() {
                            let ref out = tx.output[vout];
                            return Ok(Some(out.script_pubkey.clone()));
                        }
                    }
                }
            }
            error!("unknown utxo: {}", coin);
            return Err(SPVError::UnknownUTXO);
        }
        panic!("Configuration error. No db to get utxo.");
    }

    pub fn get_utxo_accessor<'a>(&'a self, block: &Block) -> DBUTXOAccessor<'a> {
        DBUTXOAccessor::new(self, block)
    }
}

/// A header enriched with information about its position on the blockchain
#[derive(Clone)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub log2work: f32,
    /// pointer to block if known
    pub block: Option<PRef>,
    /// pointer to filter if known
    pub filter: Option<PRef>,
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
        let mut buf = [0u8; 4];
        BigEndian::write_f32(&mut buf, self.log2work);
        buf.consensus_encode(s)?;
        if let Some(pref) = self.block {
            pref.consensus_encode(s)?;
        } else {
            PRef::invalid().consensus_encode(s)?;
        }
        if let Some(pref) = self.filter {
            pref.consensus_encode(s)?;
        } else {
            PRef::invalid().consensus_encode(s)?;
        }
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredHeader {
    fn consensus_decode(d: &mut D) -> Result<StoredHeader, encode::Error> {
        Ok(StoredHeader {
            header: Decodable::consensus_decode(d)?,
            height: Decodable::consensus_decode(d)?,
            log2work: {
                let buf: [u8; 4] = Decodable::consensus_decode(d)?;
                BigEndian::read_f32(&buf)
            },
            block: {
                let pref: PRef = Decodable::consensus_decode(d)?;
                if pref.is_valid() {
                    Some(pref)
                } else {
                    None
                }
            },
            filter: {
                let pref: PRef = Decodable::consensus_decode(d)?;
                if pref.is_valid() {
                    Some(pref)
                } else {
                    None
                }
            },
        })
    }
}

const HEADER_TIP_KEY: &[u8] = &[0u8; 1];

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
    pub filter: Option<Vec<u8>>,
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
        if let Some(ref filter) = self.filter {
            filter.consensus_encode(s)?;
        } else {
            [0u8; 0].consensus_encode(s)?;
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
                let f: Vec<u8> = Decodable::consensus_decode(d)?;
                if f.len() == 0 {
                    None
                } else {
                    Some(f)
                }
            },
        })
    }
}

/// Block stored
pub struct StoredBlock {
    pub id: Sha256dHash,
    // block height
    pub height: u32,
    // transactions
    pub txdata: Vec<Transaction>,
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredBlock {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.id.consensus_encode(s)?;
        self.height.consensus_encode(s)?;
        self.txdata.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock {
            id: Decodable::consensus_decode(d)?,
            height: Decodable::consensus_decode(d)?,
            txdata: Decodable::consensus_decode(d)?,
        })
    }
}

const UTXO_TIP: &[u8] = &[0xeeu8, 6];

pub struct StoredUTXO {
    utxo_id: u64
}

impl StoredUTXO {
    pub fn new(height: u32, tx_nr: u32, vout: u32) -> StoredUTXO {
        StoredUTXO { utxo_id: (height as u64) << 40 | (tx_nr as u64) << 16 | (vout as u64) }
    }

    pub fn height(&self) -> u32 {
        (self.utxo_id >> 40) as u32
    }

    pub fn tx_nr(&self) -> u32 {
        ((self.utxo_id >> 16) & 0xffffff) as u32
    }

    pub fn vout(&self) -> u32 {
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

fn unwind_key(block_id: &Sha256dHash) -> Sha256dHash {
    // hash again for unwind key of a block
    Sha256dHash::from_data(block_id.as_bytes())
}

pub struct DBUTXOAccessor<'a> {
    utxostore: &'a ChainDB,
    same_block_utxo: HashMap<(Sha256dHash, u32), Script>,
}

impl<'a> DBUTXOAccessor<'a> {
    pub fn new(utxostore: &'a ChainDB, block: &Block) -> DBUTXOAccessor<'a> {
        let mut acc = DBUTXOAccessor { utxostore: utxostore, same_block_utxo: HashMap::new() };
        for t in &block.txdata {
            let id = t.txid();
            for (ix, o) in t.output.iter().enumerate() {
                acc.same_block_utxo.insert((id, ix as u32), o.script_pubkey.clone());
            }
        }
        acc
    }
}


pub trait UTXOAccessor {
    fn get_utxo(&self, coin: &OutPoint) -> Result<Option<Script>, SPVError>;
}

impl<'a> UTXOAccessor for DBUTXOAccessor<'a> {
    fn get_utxo(&self, coin: &OutPoint) -> Result<Option<Script>, SPVError> {
        if let Some(r) = self.same_block_utxo.get(&(coin.txid, coin.vout)) {
            return Ok(Some(r.clone()));
        }
        self.utxostore.get_utxo(coin)
    }
}
