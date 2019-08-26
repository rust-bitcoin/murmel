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
    consensus::{Decodable, Encodable},
    network::constants::Network
};
use bip158;
use bip158::{BlockFilter, SCRIPT_FILTER, BlockFilterReader};
use bitcoin_hashes::{Hash, sha256d};
use error::MurmelError;
use filtercache::FilterCache;
use filtercalculator::TXID_FILTER;
use hammersbald::{
    BitcoinAdaptor, HammersbaldAPI, persistent, PRef,
    transient,
};
use headercache::{CachedHeader, HeaderCache};
use scriptcache::ScriptCache;
use std::{
    cmp::max,
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock}
};
use std::{
    io::Cursor,
    path::Path
};

/// Shared handle to a database storing the block chain
/// protected by an RwLock
pub type SharedChainDB = Arc<RwLock<ChainDB>>;

/// Database storing the block chain
pub struct ChainDB {
    db: BitcoinAdaptor,
    headercache: HeaderCache,
    filtercache: FilterCache,
    scriptcache: Mutex<ScriptCache>,
    network: Network
}

impl ChainDB {
    /// Create an in-memory database instance
    pub fn mem(network: Network, script_cache_size: usize) -> Result<ChainDB, MurmelError> {
        info!("working with in memory chain db");
        let db = BitcoinAdaptor::new(transient(2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        let scriptcache = Mutex::new(ScriptCache::new(script_cache_size));
        Ok(ChainDB { db, network, headercache, filtercache, scriptcache })
    }

    /// Create or open a persistent database instance identified by the path
    pub fn new(path: &Path, network: Network, script_cache_size: usize) -> Result<ChainDB, MurmelError> {
        let basename = path.to_str().unwrap().to_string();
        let db = BitcoinAdaptor::new(persistent((basename.clone()).as_str(), 100, 2)?);
        let headercache = HeaderCache::new(network);
        let filtercache = FilterCache::new();
        let scriptcache = Mutex::new(ScriptCache::new(script_cache_size));
        Ok(ChainDB { db, network, headercache, filtercache, scriptcache})
    }

    /// Initialize caches
    pub fn init(&mut self, server: bool) -> Result<(), MurmelError> {
        self.init_headers(server)?;
        if server {
            if self.scriptcache.lock().unwrap().capacity() > 0 {
                self.rebuild_cache()?;
            }
        }
        Ok(())
    }

    /// Batch updates. Updates are permanent after finishing a batch.
    pub fn batch(&mut self) -> Result<(), MurmelError> {
        self.db.batch()?;
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
                    if stored.header.prev_blockhash != sha256d::Hash::default() {
                        h = stored.header.prev_blockhash;
                    } else {
                        break;
                    }
                }
                info!("read {} headers", sl.len());
            }
        }

        if sl.is_empty() {
            let genesis = genesis_block(self.network).header;
            if let Some((cached, _, _)) = self.headercache.add_header(&genesis)? {
                info!("Initialized with genesis header {}", genesis.bitcoin_hash());
                self.db.put_hash_keyed(&cached.stored)?;
                self.db.batch()?;
                self.store_header_tip(&cached.bitcoin_hash())?;
                self.db.batch()?;
            }
            else {
                error!("Failed to initialize with genesis header");
                return Err(MurmelError::NoTip);
            }
        } else {
            info!("Caching block headers and filter headers ...");
            self.headercache.clear();
            while let Some(stored) = sl.pop_front() {
                self.headercache.add_header_unchecked(&stored);
                let block_id = stored.header.bitcoin_hash();
                if let Some(filter) = self.fetch_block_filter(&block_id, SCRIPT_FILTER)? {
                    self.filtercache.add_filter_header(filter);
                }
                if server {
                    if let Some(filter) = self.fetch_block_filter(&block_id, TXID_FILTER)? {
                        self.filtercache.add_filter(filter);
                    }
                }
            }
            info!("read {} filter header", self.filtercache.len());
        }
        Ok(())
    }

    fn rebuild_cache(&mut self) -> Result<(), MurmelError> {
        debug!("Rebuilding UTXO cache ...");
        let trunk = self.iter_trunk(0).cloned().collect::<Vec<_>>();
        for header in trunk {
            if let Some(txdata) = self.fetch_txdata(&header.bitcoin_hash())? {
                self.recache_block(&Block { header: header.stored.header.clone(), txdata }, header.stored.height);
            }
            else {
                break;
            }
            if header.stored.height % 10000 == 0 {
                debug!("cached UTXO of {} blocks, size={} ...", header.stored.height, self.scriptcache.lock().unwrap().len());
            }
        }
        debug!("Re-built UTXO cache, size={}", self.scriptcache.lock().unwrap().len());
        Ok(())
    }

    fn recache_block (&mut self, block: &Block, height: u32) {
        let mut script_cache = self.scriptcache.lock().unwrap();
        for tx in &block.txdata {
            let txid = tx.txid();
            for input in tx.input.iter() {
                script_cache.remove(&input.previous_output);
            }
            for (idx, output) in tx.output.iter().enumerate() {
                let vout = idx as u32;
                if !output.script_pubkey.is_provably_unspendable() {
                    script_cache.insert(OutPoint { txid, vout }, output.script_pubkey.clone(), height);
                }
            }
        }
    }

    /// Store a header
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<sha256d::Hash>>, Option<Vec<sha256d::Hash>>)>, MurmelError> {
        if let Some((cached, unwinds, forward)) = self.headercache.add_header(header)? {
            self.db.put_hash_keyed(&cached.stored)?;
            if let Some(forward) = forward.clone() {
                if forward.len() > 0 {
                    self.store_header_tip(forward.last().unwrap())?;
                }
            }
            return Ok(Some((cached.stored, unwinds, forward)));
        }
        Ok(None)
    }

    /// return position of hash on trunk if hash is on trunk
    pub fn pos_on_trunk(&self, hash: &sha256d::Hash) -> Option<u32> {
        self.headercache.pos_on_trunk(hash)
    }

    /// iterate trunk [from .. tip]
    pub fn iter_trunk<'a> (&'a self, from: u32) -> impl Iterator<Item=&'a CachedHeader> +'a {
        self.headercache.iter_trunk(from)
    }

    /// iterate trunk [genesis .. from] in reverse order from is the tip if not specified
    pub fn iter_trunk_rev<'a> (&'a self, from: Option<u32>) -> impl Iterator<Item=&'a CachedHeader> +'a {
        self.headercache.iter_trunk_rev(from)
    }

    /// retrieve the id of the block/header with most work
    pub fn header_tip(&self) -> Option<CachedHeader> {
        self.headercache.tip()
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &sha256d::Hash) -> Option<CachedHeader> {
        self.headercache.get_header(id)
    }

    /// Fetch a header by its id from cache
    pub fn get_header_for_height(&self, height: u32) -> Option<CachedHeader> {
        self.headercache.get_header_for_height(height)
    }

    /// locator for getheaders message
    pub fn header_locators(&self) -> Vec<sha256d::Hash> {
        self.headercache.locator_hashes()
    }

    /// Store a filter
    pub fn add_filter_header (&mut self, filter: StoredFilter) -> Result<(), MurmelError> {
        self.db.put_hash_keyed(&filter)?;
        self.filtercache.add_filter_header(filter);
        Ok(())
    }

    /// add a filter to db and cache
    pub fn add_filter (&mut self, filter: StoredFilter) -> Result<(), MurmelError> {
        self.db.put_hash_keyed(&filter)?;
        self.filtercache.add_filter(filter);
        Ok(())
    }

    /// Get a filter header from cache by filter id
    pub fn get_filter(&self, filter_id: &sha256d::Hash) -> Option<Arc<StoredFilter>> {
        self.filtercache.get_filter(filter_id)
    }

    /// Get a filter header from cache by its block id and type
    pub fn get_block_filter(&self, block_id: &sha256d::Hash, filter_type: u8) -> Option<Arc<StoredFilter>> {
        self.filtercache.get_block_filter(block_id, filter_type)
    }

    /// Store the header id with most work
    pub fn store_header_tip(&mut self, tip: &sha256d::Hash) -> Result<(), MurmelError> {
        self.db.put_keyed_encodable(HEADER_TIP_KEY, tip)?;
        Ok(())
    }

    /// Find header id with most work
    pub fn fetch_header_tip(&self) -> Result<Option<sha256d::Hash>, MurmelError> {
        Ok(self.db.get_keyed_decodable::<sha256d::Hash>(HEADER_TIP_KEY)?.map(|(_, h)| h.clone()))
    }

    /// Read header from the DB
    pub fn fetch_header(&self, id: &sha256d::Hash) -> Result<Option<StoredHeader>, MurmelError> {
        Ok(self.db.get_hash_keyed::<StoredHeader>(id)?.map(|(_, header)| header))
    }

    /// Store a calculated filter
    pub fn add_calculated_filter(&mut self, previous: &sha256d::Hash, filter: &BlockFilter) -> Result<(), MurmelError> {
        let stored_filter = StoredFilter{block_id: filter.block_hash, previous: previous.clone(),
            filter_hash: sha256d::Hash::hash(filter.content.as_slice()), filter: Some(filter.content.clone()), filter_type: filter.filter_type };
        if filter.filter_type == TXID_FILTER {
            self.db.put_hash_keyed(&stored_filter)?;
            self.filtercache.add_filter(stored_filter);
        }
        else {
            self.db.put_hash_keyed(&stored_filter)?;
            self.filtercache.add_filter_header(stored_filter);
        }
        Ok(())
    }

    /// Read filter from DB
    pub fn fetch_block_filter(&self, block_id: &sha256d::Hash, filter_type: u8) -> Result<Option<StoredFilter>, MurmelError> {
        Ok(self.db.get_hash_keyed::<StoredFilter>(&StoredFilter::storage_id(block_id, filter_type))?.map(|(_, filter)| filter))
    }

    /// Check if the DB may have a block. This might return false positive but is really quick.
    pub fn may_have_block (&self, block_id: &sha256d::Hash) -> Result<bool, MurmelError> {
        Ok(self.db.may_have_hash_key (block_id)?)
    }

    /// read a block from DB
    pub fn fetch_stored_block(&self, block_id: &sha256d::Hash) -> Result<Option<StoredBlock>, MurmelError> {
        if let Some((_, block)) = self.db.get_hash_keyed::<StoredBlock>(block_id)? {
            return Ok(Some(block));
        }
        return Ok(None)
    }

    /// read transactions of a block
    pub fn fetch_txdata(&self, block_id: &sha256d::Hash) -> Result<Option<Vec<Transaction>>, MurmelError> {
        let mut txdata = Vec::new();
        if let Some((_, block)) = self.db.get_hash_keyed::<StoredBlock>(block_id)? {
            for txref in block.txrefs {
                txdata.push(self.db.get_decodable::<Transaction>(PRef::from(txref))?.1);
            }
            return Ok(Some(txdata));
        }
        return Ok(None)
    }

    /// read a single transaction
    fn fetch_transaction (&self, txref: PRef) -> Result<Transaction, MurmelError> {
        let (_, tx) = self.db.get_decodable::<Transaction>(txref)?;
        return Ok(tx);
    }

    /// store a block
    pub fn store_block(&mut self, block: &Block) -> Result<PRef, MurmelError> {
        if let Some(header) = self.headercache.get_header(&block.bitcoin_hash()) {
            debug!("store block  {:6} {} tx: {}", header.stored.height, header.bitcoin_hash(), block.txdata.len());
            let txids = block.txdata.iter().map(|tx| tx.txid()).collect::<Vec<_>>();
            let mut txrefs = Vec::with_capacity(txids.len());
            for tx in &block.txdata {
                txrefs.push(self.db.put_encodable(tx)?.as_u64());
            }
            let pref = self.db.put_hash_keyed(&StoredBlock { header: header.stored, txids, txrefs })?;
            return Ok(pref);
        }
        panic!("should not call store block before header is known {}", block.bitcoin_hash());
    }

    /// collect output scripts of a block into a cache
    pub fn cache_scripts(&mut self, block: &Block, height: u32) {
        let mut script_cache = self.scriptcache.lock().unwrap();
        for tx in &block.txdata {
            let txid = tx.txid();
            for (idx, output) in tx.output.iter().enumerate() {
                let vout = idx as u32;
                if !output.script_pubkey.is_provably_unspendable() {
                    script_cache.insert(OutPoint { txid, vout }, output.script_pubkey.clone(), height);
                }
            }
        }
        if height % 10000 == 0 {
            debug!("UTXO cache at height {} size={}", height, script_cache.len());
        }
    }

    fn get_scripts(&self, mut remains: Vec<Vec<u8>>, mut sofar: Vec<Script>) -> Result<Vec<Script>, MurmelError> {
        remains.sort();
        if remains.len() > 0 {
            let from = self.scriptcache.lock().unwrap().complete_after();
            debug!("lookup {} input coins in filters before height {} ... ", remains.len(), from);
            let mapped = remains.chunks(max(50, remains.len()/8)).map(|remains| {
                let remains = remains.to_vec();
                self.resolve_with_filters(from, remains)
            }).flatten().collect::<Vec<_>>();
            sofar.extend (mapped.iter().map(|(s, _)|s.clone()));
            if let Some(first) = mapped.iter().map(|(_, h)|h).min() {
                debug!("... highest block with filter match {}", first);
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

    fn resolve_with_filters (&self, from: u32, mut remains: Vec<Vec<u8>>) -> Vec<(Script, u32)> {
        let mut sofar = Vec::new();
        for header in self.iter_trunk_rev(Some(from)) {
            let block_id = header.bitcoin_hash();
            // if filter is known for this block
            if self.get_block_filter(&block_id, TXID_FILTER).is_some() {
                if let Some(ref filter) = self.fetch_block_filter(&block_id, TXID_FILTER).unwrap() {
                    if let Some(ref filter) = filter.filter {
                        // check in a single pass read if any coins we search for might be in the filter for this block
                        let reader = BlockFilterReader::new(&block_id);
                        if reader.match_any(&mut Cursor::new(filter.as_slice()), &mut remains.iter().map(|v| &v.as_slice()[0..32])).unwrap() {
                            // do we have the block ?
                            if let Some(block) = self.fetch_stored_block(&block_id).unwrap() {
                                // for all transactions
                                for (txpos, txid) in block.txids.iter().enumerate() {
                                    // check if any or many! outputs of this transaction are those we search for
                                    while let Ok(pos) = remains.binary_search_by(|r| r[0..32].cmp(&txid[..])) {
                                        // a transaction that we are interested in
                                        let coin = OutPoint::consensus_decode(&mut Cursor::new(remains[pos].as_slice())).unwrap();
                                        // get the script
                                        let tx = self.fetch_transaction(PRef::from(block.txrefs[txpos])).unwrap();
                                        sofar.push((tx.output[coin.vout as usize].script_pubkey.clone(), header.stored.height));
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
        }

        sofar
    }

    /// get an object capable of finding spent scripts
    pub fn get_script_accessor<'a>(&'a mut self, block: &Block) -> DBScriptAccessor<'a> {
        let mut accessor = DBScriptAccessor::new(self, block);
        accessor.compute(block);
        accessor
    }
}


/// an object capable of retrieving spent scripts of a block
pub struct DBScriptAccessor<'a> {
    db: &'a mut ChainDB,
    scripts: HashMap<OutPoint, Script>,
}

impl<'a> DBScriptAccessor<'a> {
    /// create a new script accessor for a block
    pub fn new(db: &'a mut ChainDB, block: &Block) -> DBScriptAccessor<'a> {
        DBScriptAccessor { db: db, scripts: HashMap::new() }
    }

    /// pre-compute scripts for a block for resolve
    pub fn compute(&mut self, block: &Block) {
        for t in &block.txdata {
            let txid = t.txid();
            for (vout, o) in t.output.iter().enumerate() {
                self.scripts.insert(OutPoint{txid, vout: vout as u32}, o.script_pubkey.clone());
            }
            let mut remains = Vec::new();
            let mut scriptcache = self.db.scriptcache.lock().unwrap();
            for input in &t.input {
                let coin = input.previous_output;
                if let Some(script) = scriptcache.remove(&coin) {
                    self.scripts.insert(coin, script);
                }
                if self.scripts.get(&coin).is_none() {
                    remains.push(coin);
                }
            }
        }
    }

    /// find the script for a coin (UTXO)
    pub fn resolve (&self, coin: &OutPoint) -> Result<Script, bip158::Error> {
        if let Some(script) = self.scripts.get(coin) {
            return Ok (script.clone())
        }
        Err(bip158::Error::UtxoMissing(coin.clone()))
    }
}

/// A header enriched with information about its position on the blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work
    pub log2work: f64
}

// need to implement if put_hash_keyed and get_hash_keyed should be used
impl BitcoinHash for StoredHeader {
    fn bitcoin_hash(&self) -> sha256d::Hash {
        self.header.bitcoin_hash()
    }
}

const HEADER_TIP_KEY: &[u8] = &[0u8; 1];

/// Filter stored
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredFilter {
    /// filter type
    pub filter_type: u8,
    /// block
    pub block_id: sha256d::Hash,
    /// hash of the filter content
    pub filter_hash: sha256d::Hash,
    /// previous filter id
    pub previous: sha256d::Hash,
    /// filter content
    pub filter: Option<Vec<u8>>,
}

impl StoredFilter {
    /// the filter's unique id
    pub fn filter_id(&self) -> sha256d::Hash {
        let mut id_data = [0u8; 64];
        id_data[0..32].copy_from_slice(&self.filter_hash[..]);
        id_data[32..].copy_from_slice(&self.previous[..]);
        sha256d::Hash::hash(&id_data)
    }

    /// compute the id used to store this filter
    pub fn storage_id (block_id: &sha256d::Hash, filter_type: u8) -> sha256d::Hash {
        let mut id_data = [0u8; 33];
        id_data[0..32].copy_from_slice(&block_id[..]);
        id_data[32] = filter_type;
        sha256d::Hash::hash(&id_data)
    }
}

// stored with a key derivable from block_id and filter type
impl BitcoinHash for StoredFilter {
    fn bitcoin_hash(&self) -> sha256d::Hash {
        Self::storage_id(&self.block_id, self.filter_type)
    }
}

/// Block stored
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBlock {
    /// the block's unique id
    pub header: StoredHeader,
    /// ids of transaction within the block
    pub txids: Vec<sha256d::Hash>,
    /// persistent references to stored transactions
    pub txrefs: Vec<u64>
}

impl BitcoinHash for StoredBlock {
    fn bitcoin_hash(&self) -> sha256d::Hash {
        self.header.bitcoin_hash()
    }
}



