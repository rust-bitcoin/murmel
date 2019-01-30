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
use error::MurmelError;
use filtercache::FilterCache;
use headercache::{HeaderCache, HeaderIterator};
use blockfilter::{BlockFilter, BlockFilterReader, COIN_FILTER, SCRIPT_FILTER};
use scriptcache::ScriptCache;

use hammersbald::{
    BitcoinAdaptor, HammersbaldAPI, persistent, PRef,
    transient,
};

use rayon::prelude::{ParallelIterator, ParallelSlice};

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, RwLock, Mutex},
};
use std::{
    path::Path,
    io::Cursor
};

pub type SharedChainDB = Arc<RwLock<ChainDB>>;

pub struct ChainDB {
    light: BitcoinAdaptor,
    heavy: Option<BitcoinAdaptor>,
    headercache: HeaderCache,
    filtercache: FilterCache,
    scriptcache: Mutex<ScriptCache>,
    network: Network,
}

impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network, heavy: bool, server: bool, script_cache_size: usize) -> Result<ChainDB, MurmelError> {
        info!("working with in memory chain db");
        let light = BitcoinAdaptor::new(transient(2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new(server);
        let scriptcache = Mutex::new(ScriptCache::new(script_cache_size));
        if heavy {
            let heavy = Some(BitcoinAdaptor::new(transient(2)?));
            Ok(ChainDB { light, heavy, network, headercache, filtercache, scriptcache })
        } else {
            Ok(ChainDB { light, heavy: None, network, headercache, filtercache, scriptcache })
        }
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network, heavy: bool, server: bool, script_cache_size: usize) -> Result<ChainDB, MurmelError> {
        let basename = path.to_str().unwrap().to_string();
        let light = BitcoinAdaptor::new(persistent((basename.clone() + ".h").as_str(), 100, 2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new(server);
        let scriptcache = Mutex::new(ScriptCache::new(script_cache_size));
        if heavy {
            let heavy = Some(BitcoinAdaptor::new(persistent((basename + ".b").as_str(), 1000, 2)?));
            Ok(ChainDB { light, heavy, network, headercache, filtercache, scriptcache })
        } else {
            Ok(ChainDB { light, heavy: None, network, headercache, filtercache, scriptcache })
        }
    }

    pub fn init(&mut self, server: bool, rebuild_cache: bool) -> Result<(), MurmelError> {
        self.init_headers(server)?;
        if rebuild_cache {
            self.rebuild_cache()?;
        }
        Ok(())
    }

    pub fn batch(&mut self) -> Result<(), MurmelError> {
        self.light.batch()?;
        if let Some(ref mut heavy) = self.heavy {
            heavy.batch()?;
        }
        Ok(())
    }

    fn init_headers(&mut self, server: bool) -> Result<(), MurmelError> {
        if server {
            info!("Running as filter server");
        }
        else {
            info!("Running as filter client");
        }
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
                let block_id = stored.header.bitcoin_hash();
                if let Some(filter) = self.fetch_filter(&block_id, SCRIPT_FILTER)? {
                    self.filtercache.add_filter(&filter);
                }
                if let Some(filter) = self.fetch_filter(&block_id, COIN_FILTER)? {
                    self.filtercache.add_filter(&filter);
                }
            }
            info!("read {} filter header", self.filtercache.len());
        }
        Ok(())
    }

    fn rebuild_cache(&mut self) -> Result<(), MurmelError> {
        debug!("rebuilding cache ...");
        let trunk = self.iter_trunk(0).cloned().collect::<Vec<_>>();
        for header in trunk {
            if let Some(txdata) = self.fetch_txdata(&header.header.bitcoin_hash())? {
                self.cache_scripts(&Block { header: header.header.clone(), txdata }, header.height);
                if header.height % 10000 == 0 {
                    debug!("cached coins of {} blocks, cache size {} ...", header.height, self.scriptcache.lock().unwrap().len());
                }
            }
            else {
                break;
            }
        }
        debug!("re-built coin cache.");
        Ok(())
    }

    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, MurmelError> {
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

    // itarate from any hash to genesis. start_with might not be on trunk. result is an iterator of [genesis .. from]
    pub fn iter_to_genesis<'a>(&'a self, from: Option<Sha256dHash>) -> HeaderIterator<'a> {
        return self.headercache.iter_to_genesis(from);
    }

    // return position of hash on trunk if hash is on trunk
    pub fn pos_on_trunk(&self, hash: &Sha256dHash) -> Option<u32> {
        self.headercache.pos_on_trunk(hash)
    }

    // iterate trunk (after .. tip]
    pub fn iter_trunk<'a> (&'a self, after: u32) -> impl Iterator<Item=&'a StoredHeader> +'a {
        self.headercache.iter_trunk(after)
    }

    // iterate trunk [genesis .. from] in reverse order from is the tip if not specified
    pub fn iter_trunk_rev<'a> (&'a self, from: Option<u32>) -> impl Iterator<Item=&'a StoredHeader> +'a {
        self.headercache.iter_trunk_rev(from)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<StoredHeader> {
        self.headercache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        self.headercache.get_header(id)
    }

    /// Fetch a header by its id from cache
    pub fn get_header_for_height(&self, height: u32) -> Option<StoredHeader> {
        self.headercache.get_header_for_height(height)
    }

    // locator for getheaders message
    pub fn header_locators(&self) -> Vec<Sha256dHash> {
        self.headercache.locator_hashes()
    }

    pub fn add_filter (&mut self, filter: StoredFilter) -> Result<(), MurmelError> {
        self.store_filter(&filter)?;
        self.filtercache.add_filter(&filter);
        Ok(())
    }

    pub fn get_filter(&self, filter_id: &Sha256dHash) -> Option<Arc<StoredFilter>> {
        self.filtercache.get_filter(filter_id)
    }

    pub fn get_block_filter(&self, block_id: &Sha256dHash, filter_type: u8) -> Option<Arc<StoredFilter>> {
        self.filtercache.get_block_filter(block_id, filter_type)
    }

    pub fn store_header(&mut self, stored: &StoredHeader) -> Result<PRef, MurmelError> {
        Ok(self.light.put_hash_keyed(stored)?)
    }

    pub fn store_header_tip(&mut self, tip: &Sha256dHash) -> Result<(), MurmelError> {
        self.light.put_keyed_encodable(HEADER_TIP_KEY, tip)?;
        Ok(())
    }

    pub fn fetch_header_tip(&self) -> Result<Option<Sha256dHash>, MurmelError> {
        Ok(self.light.get_keyed_decodable::<Sha256dHash>(HEADER_TIP_KEY)?.map(|(_, h)| h.clone()))
    }

    pub fn fetch_header(&self, id: &Sha256dHash) -> Result<Option<StoredHeader>, MurmelError> {
        Ok(self.light.get_hash_keyed::<StoredHeader>(id)?.map(|(_, header)| header))
    }

    pub fn store_filter(&mut self, filter: &StoredFilter) -> Result<PRef, MurmelError> {
        Ok(self.light.put_hash_keyed(filter)?)
    }

    pub fn fetch_filter(&self, block_id: &Sha256dHash, filter_type: u8) -> Result<Option<StoredFilter>, MurmelError> {
        let mut id_data = [0u8; 33];
        id_data[0..32].copy_from_slice(&block_id.as_bytes()[..]);
        id_data[32] = filter_type;
        let key = Sha256dHash::from_data(&id_data);
        Ok(self.light.get_hash_keyed::<StoredFilter>(&key)?.map(|(_, filter)| filter))
    }

    pub fn store_known_filter (&mut self, previous_script: &Sha256dHash, previous_coin: &Sha256dHash, script_filter: &BlockFilter, coin_filter: &BlockFilter) -> Result<(), MurmelError> {
        let stored_script_filter = StoredFilter{block_id: script_filter.block, previous: previous_script.clone(),
            filter_hash: Sha256dHash::from_data(script_filter.content.as_slice()), filter: Some(script_filter.content.clone()), filter_type: script_filter.filter_type };
        self.store_filter(&stored_script_filter)?;
        self.filtercache.add_filter(&stored_script_filter);

        let stored_coin_filter = StoredFilter{block_id: coin_filter.block, previous: previous_coin.clone(),
            filter_hash: Sha256dHash::from_data(coin_filter.content.as_slice()), filter: Some(coin_filter.content.clone()), filter_type: coin_filter.filter_type };
        self.store_filter(&stored_coin_filter)?;
        self.filtercache.add_filter(&stored_coin_filter);
        Ok(())
    }

    pub fn may_have_block (&self, block_id: &Sha256dHash) -> Result<bool, MurmelError> {
        if let Some(ref heavy) = self.heavy {
            return Ok(heavy.may_have_hash_key (block_id)?);
        }
        Ok(false)
    }

    pub fn fetch_stored_block(&self, block_id: &Sha256dHash) -> Result<Option<StoredBlock>, MurmelError> {
        if let Some(ref heavy) = self.heavy {
            if let Some((_, block)) = heavy.get_hash_keyed::<StoredBlock>(block_id)? {
                return Ok(Some(block));
            }
            return Ok(None)
        }
        panic!("configuration error: no block store");
    }

    pub fn fetch_txdata(&self, block_id: &Sha256dHash) -> Result<Option<Vec<Transaction>>, MurmelError> {
        if let Some(ref heavy) = self.heavy {
            let mut txdata = Vec::new();
            if let Some((_, block)) = heavy.get_hash_keyed::<StoredBlock>(block_id)? {
                for txref in block.txrefs {
                    txdata.push(heavy.get_decodable::<Transaction>(txref)?.1);
                }
                return Ok(Some(txdata));
            }
            return Ok(None)
        }
        panic!("configuration error: no block store");
    }

    pub fn fetch_transaction (&self, txref: PRef) -> Result<Transaction, MurmelError> {
        if let Some(ref heavy) = self.heavy {
            let (_, tx) = heavy.get_decodable::<Transaction>(txref)?;
            return Ok(tx);
        }
        panic!("configuration error: no block store");
    }

    pub fn store_block(&mut self, block: &Block) -> Result<PRef, MurmelError> {
        if let Some(header) = self.headercache.get_header(&block.bitcoin_hash()) {
            let pref;
            if let Some(ref mut heavy) = self.heavy {
                let txids = block.txdata.iter().map(|tx| tx.txid()).collect::<Vec<_>>();
                let mut txrefs = Vec::with_capacity(txids.len());
                for tx in &block.txdata {
                    txrefs.push(heavy.put_encodable(tx)?);
                }
                pref = heavy.put_hash_keyed(&StoredBlock { id: block.bitcoin_hash(), txids, txrefs })?;
            } else {
                panic!("Configuration error. No db to store block.");
            }
            return Ok(pref);
        }
        panic!("should not call store block before header is known {}", block.bitcoin_hash());
    }

    pub fn cache_scripts(&mut self, block: &Block, height: u32) {
        let block_id = Arc::new(block.bitcoin_hash());
        let mut script_cache = self.scriptcache.lock().unwrap();
        for (i, tx) in block.txdata.iter().enumerate() {
            let tx_nr = i as u32;
            let txid = tx.txid();
            for (idx, output) in tx.output.iter().enumerate() {
                let vout = idx as u32;
                if !output.script_pubkey.is_provably_unspendable() {
                    script_cache.insert(OutPoint { txid, vout }, output.script_pubkey.clone(), height);
                }
            }
        }
    }

    pub fn get_scripts(&self, coins: Vec<OutPoint>, mut sofar: Vec<Script>) -> Result<Vec<Script>, MurmelError> {
        let mut remains = Vec::with_capacity(coins.len());
        {
            // check in script cache
            let mut scriptcache = self.scriptcache.lock().unwrap();
            for coin in &coins {
                if let Some(script) = scriptcache.remove(coin) {
                    sofar.push(script);
                } else {
                    let mut buf = Vec::new();
                    coin.consensus_encode(&mut buf)?;
                    remains.push(buf);
                }
            }
        }
        remains.sort();
        if remains.len() > 0 {
            let from = self.scriptcache.lock().unwrap().complete_after();
            if coins.len () > 0 {
                debug!("lookup {} input coins {} in cache {} % {} in filters before height {}", coins.len(), coins.len() - remains.len(), ((coins.len() - remains.len()) * 100) / coins.len(), remains.len(), from);
            } else {
                debug!("this block has only a coinbase transaction.");
            }
            let len = remains.len();
            let mapped = remains.par_chunks(50).map(|remains| {
                let remains = remains.to_vec();
                self.resolve_with_filters(from, remains)
            }).flatten().collect::<Vec<_>>();
            sofar.extend (mapped.iter().map(|(s, _)|s.clone()));
            if let Some(first) = mapped.iter().map(|(_, h)|h).min() {
                debug!("first block with filter match {}", first);
            }
        }
        // are we done?
        if remains.len () > sofar.len() {
            let coins = remains.iter().map(|v| OutPoint::consensus_decode(&mut Cursor::new(v.as_slice())).unwrap())
                .map(|o| format!("{} {}", o.txid, o.vout)).collect::<Vec<_>>();
            error!("can not find coins {:?}", coins);
            return Err(MurmelError::UnknownUTXO);
        }
        Ok(sofar)
    }

    fn resolve_with_filters (&self, from: u32, mut remains: Vec<Vec<u8>>) -> (Vec<(Script, u32)>) {
        let mut sofar = Vec::new();
        for header in self.iter_trunk_rev(Some(from)) {
            let block_id = header.header.bitcoin_hash();
            // if filter is known for this block
            if let Some(filter) = self.get_block_filter(&block_id, COIN_FILTER) {
                if let Some(ref filter) = filter.filter {
                    // check in a single pass read if any coins we search for might be in the filter for this block
                    let reader = BlockFilterReader::new(&block_id).unwrap();
                    if reader.match_any(&mut Cursor::new(filter), &remains).unwrap() {
                        // do we have the block ?
                        if let Some(block) = self.fetch_stored_block(&block_id).unwrap() {
                            // for all transactions
                            for (txpos, txid) in block.txids.iter().enumerate() {
                                // check if any or many! outputs of this transaction are those we search for
                                while let Ok(pos) = remains.binary_search_by(|r| r[0..32].cmp(txid.as_bytes())) {
                                    // a transaction that we are interested in
                                    let coin = OutPoint::consensus_decode(&mut Cursor::new(remains[pos].as_slice())).unwrap();
                                    // get the script
                                    let tx = self.fetch_transaction(block.txrefs[txpos]).unwrap();
                                    sofar.push((tx.output[coin.vout as usize].script_pubkey.clone(), header.height));
                                    // one less to worry about
                                    remains.remove(pos);
                                    // are we done?
                                    if remains.len() == 0 {
                                        break;
                                    }
                                }
                                // are we done?
                                if remains.len() == 0 {
                                    break;
                                }
                            }
                            // are we done?
                            if remains.len() == 0 {
                                break;
                            }
                        }
                    }
                }
            }
        }
        sofar
    }

    pub fn get_script_accessor<'a>(&'a self, block: &Block) -> DBScriptAccessor<'a> {
        DBScriptAccessor::new(self, block)
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
        let mut buf = [0u8; 4];
        BigEndian::write_f32(&mut buf, self.log2work);
        buf.consensus_encode(s)?;
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
            }
        })
    }
}

const HEADER_TIP_KEY: &[u8] = &[0u8; 1];

/// Filter stored
#[derive(Clone)]
pub struct StoredFilter {
    /// filter type
    pub filter_type: u8,
    /// block
    pub block_id: Sha256dHash,
    /// hash of the filter content
    pub filter_hash: Sha256dHash,
    /// previous filter id
    pub previous: Sha256dHash,
    /// filter content
    pub filter: Option<Vec<u8>>,
}

impl StoredFilter {
    pub fn filter_id(&self) -> Sha256dHash {
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&self.filter_hash.as_bytes()[..]);
        id_data[0..32].copy_from_slice(&self.previous.as_bytes()[..]);
        Sha256dHash::from_data(&id_data)
    }
}

// stored with a key derivable from block_id and filter type
impl BitcoinHash for StoredFilter {
    fn bitcoin_hash(&self) -> Sha256dHash {
        let mut id_data = [0u8; 33];
        id_data[0..32].copy_from_slice(&self.block_id.as_bytes()[..]);
        id_data[32] = self.filter_type;
        Sha256dHash::from_data(&id_data)
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredFilter {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.filter_type.consensus_encode(s)?;
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
            filter_type: Decodable::consensus_decode(d)?,
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
    // transactions
    pub txids: Vec<Sha256dHash>,
    pub txrefs: Vec<PRef>
}

impl BitcoinHash for StoredBlock {
    fn bitcoin_hash(&self) -> Sha256dHash {
        self.id
    }
}

// implement encoder. tedious just repeat the consensus_encode lines
impl<S: Encoder> Encodable<S> for StoredBlock {
    fn consensus_encode(&self, s: &mut S) -> Result<(), encode::Error> {
        self.id.consensus_encode(s)?;
        self.txids.consensus_encode(s)?;
        self.txrefs.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredBlock {
    fn consensus_decode(d: &mut D) -> Result<StoredBlock, encode::Error> {
        Ok(StoredBlock {
            id: Decodable::consensus_decode(d)?,
            txids: Decodable::consensus_decode(d)?,
            txrefs: Decodable::consensus_decode(d)?
        })
    }
}

pub struct DBScriptAccessor<'a> {
    db: &'a ChainDB,
    prev_block: Sha256dHash,
    same_block_scripts: HashMap<OutPoint, Script>,
}

impl<'a> DBScriptAccessor<'a> {
    pub fn new(db: &'a ChainDB, block: &Block) -> DBScriptAccessor<'a> {
        let mut acc = DBScriptAccessor { db: db, same_block_scripts: HashMap::new(), prev_block: block.header.prev_blockhash };
        for t in &block.txdata {
            let txid = t.txid();
            for (vout, o) in t.output.iter().enumerate() {
                acc.same_block_scripts.insert(OutPoint{txid, vout: vout as u32}, o.script_pubkey.clone());
            }
        }
        acc
    }
}


pub trait ScriptAccessor {
    fn get_scripts(&self, coins: Vec<OutPoint>) -> Result<Vec<Script>, MurmelError>;
}

impl<'a> ScriptAccessor for DBScriptAccessor<'a> {
    fn get_scripts(&self, coins: Vec<OutPoint>) -> Result<Vec<Script>, MurmelError> {
        let mut sofar = Vec::with_capacity(coins.len());
        let mut remains = Vec::with_capacity(coins.len());
        for coin in coins {
            if let Some(r) = self.same_block_scripts.get(&coin) {
                sofar.push(r.clone());
            }
            else {
                remains.push(coin);
            }
        }
        self.db.get_scripts(remains, sofar)
    }
}
