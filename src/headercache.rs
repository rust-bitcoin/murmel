//
// Copyright 2019 Tamas Blummer
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
//! # Cache of headers and the chain with most work
//!

use bitcoin::{
    BitcoinHash,
    blockdata::block::BlockHeader,
    network::constants::Network,
    util::{
        hash::Sha256dHash,
        uint::Uint256,
    },
};
use error::SPVError;
use headerstore::{HeaderStore, StoredHeader};
use std::{
    collections::HashMap,
    sync::Arc,
};

pub struct HeaderCache {
    // network
    network: Network,
    // all known headers
    headers: HashMap<Arc<Sha256dHash>, StoredHeader>,
    // header chain with most work
    trunk: Vec<Arc<Sha256dHash>>,
}

const EXPECTED_CHAIN_LENGTH: usize = 600000;

impl HeaderCache {
    pub fn new(network: Network) -> HeaderCache {
        HeaderCache { network, headers: HashMap::with_capacity(EXPECTED_CHAIN_LENGTH), trunk: Vec::with_capacity(EXPECTED_CHAIN_LENGTH) }
    }

    /// add a Bitcoin header
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, bool)>, SPVError> {
        if self.headers.get(&header.bitcoin_hash()).is_some() {
            return Ok(None);
        }
        if header.prev_blockhash != Sha256dHash::default() {
            let previous;
            if let Some(prev) = self.headers.get(&header.prev_blockhash) {
                previous = prev.clone();
            } else {
                return Err(SPVError::UnconnectedHeader);
            }
            let (stored, new_tip) = self.add_header_to_tree(&previous, header)?;
            return Ok(Some((stored, new_tip)));
        } else {
            let new_tip = Arc::new(header.bitcoin_hash());
            let stored = StoredHeader {
                header: header.clone(),
                height: 0,
                log2work: Self::log2(header.work()),
            };
            self.trunk.push(new_tip.clone());
            self.headers.insert(new_tip.clone(), stored.clone());
            return Ok(Some((stored, true)));
        }
    }

    fn log2(work: Uint256) -> f32 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(work.0[2] == 0 && work.0[3] == 0);
        ((work.0[0] as u128 + ((work.0[1] as u128) << 64)) as f32).log2()
    }

    fn exp2(n: f32) -> Uint256 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(n < 128.0);
        let e: u128 = n.exp2() as u128;
        let mut b = [0u64; 4];
        b[0] = e as u64;
        b[1] = (e >> 64) as u64;
        Uint256(b)
    }

    fn max_target() -> Uint256 {
        Uint256::from_u64(0xFFFF).unwrap() << 208
    }

    /// POW comments and code based on a work by Andrew Poelstra
    fn add_header_to_tree(&mut self, prev: &StoredHeader, next: &BlockHeader) -> Result<(StoredHeader, bool), SPVError> {
        const DIFFCHANGE_INTERVAL: u32 = 2016;
        const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
        const TARGET_BLOCK_SPACING: u32 = 600;

        let required_work =
        // Compute required difficulty if this is a diffchange block
            if (prev.height + 1) % DIFFCHANGE_INTERVAL == 0 {
                let timespan = {
                    // Scan back DIFFCHANGE_INTERVAL blocks
                    let mut scan = prev;
                    if self.tip_hash() == Some(scan.header.prev_blockhash) {
                        scan = self.headers.get(&self.trunk[self.trunk.len() - DIFFCHANGE_INTERVAL as usize - 2]).unwrap();
                    } else {
                        for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                            if let Some(header) = self.headers.get(&scan.header.prev_blockhash) {
                                scan = header;
                            } else {
                                return Err(SPVError::UnconnectedHeader);
                            }
                        }
                    }
                    // Get clamped timespan between first and last blocks
                    match prev.header.time - scan.header.time {
                        n if n < DIFFCHANGE_TIMESPAN / 4 => DIFFCHANGE_TIMESPAN / 4,
                        n if n > DIFFCHANGE_TIMESPAN * 4 => DIFFCHANGE_TIMESPAN * 4,
                        n => n
                    }
                };
                // Compute new target
                let mut target = prev.header.target();
                target = target.mul_u32(timespan);
                target = target / Uint256::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
                // Clamp below MAX_TARGET (difficulty 1)
                let max = Self::max_target();
                if target > max { target = max };
                // Compactify (make expressible in the 8+24 nBits float format)
                Self::satoshi_the_precision(target)
                // On non-diffchange blocks, Testnet has a rule that any 20-minute-long
                // block interval resets the difficulty to 1
            } else if self.network == Network::Testnet &&
                prev.header.time > prev.header.time + 2 * TARGET_BLOCK_SPACING {
                Self::max_target()
                // On the other hand, if we are in Testnet and the block interval is less
                // than 20 minutes, we need to scan backward to find a block for which the
                // previous rule did not apply, to find the "real" difficulty.
            } else if self.network == Network::Testnet {
                // Scan back DIFFCHANGE_INTERVAL blocks
                let mut scan = prev;
                let mut height = prev.height + 1;
                let max_target = Self::max_target();
                while height % DIFFCHANGE_INTERVAL != 0 && scan.header.target() == max_target {
                    if let Some(header) = self.headers.get(&scan.header.prev_blockhash) {
                        scan = header;
                        height = header.height;
                    } else {
                        return Err(SPVError::UnconnectedHeader);
                    }
                }
                scan.header.target()
                // Otherwise just use the last block's difficulty
            } else {
                prev.header.target()
            };

        if next.spv_validate(&required_work).is_err() {
            return Err(SPVError::SpvBadProofOfWork);
        }

        let stored = StoredHeader {
            header: next.clone(),
            height: prev.height + 1,
            log2work: Self::log2(next.work() + Self::exp2(prev.log2work)),
        };
        let next_hash = Arc::new(next.bitcoin_hash());

        self.headers.insert(next_hash.clone(), stored.clone());

        if let Some(tip) = self.tip() {
            if tip.log2work < stored.log2work {
                let mut ph = *next_hash.clone();
                while !self.is_on_trunk(&ph) {
                    if let Some(h) = self.headers.get(&ph) {
                        ph = h.header.prev_blockhash;
                    } else {
                        return Err(SPVError::UnconnectedHeader);
                    }
                }
                if let Some(pos) = self.trunk.iter().rposition(|h| { **h == ph }) {
                    if pos < self.trunk.len() - 1 {
                        self.trunk.truncate(pos + 1);
                    }
                } else {
                    return Err(SPVError::UnconnectedHeader);
                }

                let mut new_trunk = vec!(next_hash);
                if let Some(last) = self.trunk.last() {
                    let mut h = &stored;
                    while **last != h.header.prev_blockhash {
                        let hh = Arc::new(h.header.bitcoin_hash());
                        new_trunk.push(hh.clone());
                        if let Some(p) = self.headers.get(&hh) {
                            h = p;
                        } else {
                            return Err(SPVError::UnconnectedHeader);
                        }
                    }
                }
                for h in new_trunk.iter().rev() {
                    self.trunk.push(h.clone());
                }
                return Ok((stored, true));
            } else {
                self.trunk.push(next_hash);
                return Ok((stored, false));
            }
        } else {
            return Err(SPVError::NoTip);
        }
    }

    /// is the hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        self.trunk.iter().rposition(|e| { **e == *hash }).is_some()
    }

    /// is the hash part of the trunk not later than until?
    pub fn is_on_trunk_until(&self, hash: &Sha256dHash, until: &Sha256dHash) -> bool {
        if let Some(p1) = self.trunk.iter().rposition(|e| { **e == *until }) {
            if let Some(p2) = self.trunk.iter().rposition(|e|{**e == *hash}) {
                return p2 <= p1;
            }
        }
        false
    }

    /// retrieve the id of the block/header with most work
    pub fn tip(&self) -> Option<StoredHeader> {
        if let Some(id) = self.tip_hash() {
            return self.get_header(&id);
        }
        None
    }

    pub fn tip_hash(&self) -> Option<Sha256dHash> {
        if let Some(tip) = self.trunk.last() {
            return Some(**tip);
        }
        None
    }

    pub fn unwind_tip (&mut self) -> Option<Sha256dHash> {
        if self.trunk.len () > 0 {
            let tip = *self.trunk.remove(self.trunk.len() - 1);
            self.headers.remove(&tip);
            return Some(tip);
        }
        None
    }

    /// This function emulates the `GetCompact(SetCompact(n))` in the Satoshi code,
    /// which drops the precision to something that can be encoded precisely in
    /// the nBits block header field. Savour the perversity. This is in Bitcoin
    /// consensus code. What. Gaah!
    fn satoshi_the_precision(n: Uint256) -> Uint256 {
        use bitcoin::util::BitArray;

        // Shift by B bits right then left to turn the low bits to zero
        let bits = 8 * ((n.bits() + 7) / 8 - 3);
        let mut ret = n >> bits;
        // Oh, did I say B was that fucked up formula? I meant sometimes also + 8.
        if ret.bit(23) {
            ret = (ret >> 8) << 8;
        }
        ret << bits
    }

    /// Fetch a header by its id from cache
    pub fn get_header(&self, id: &Sha256dHash) -> Option<StoredHeader> {
        if let Some(header) = self.headers.get(id) {
            return Some(header.clone());
        }
        None
    }

    /// initialize cache from HeaderStore
    pub fn init_cache(&mut self, header_store: &HeaderStore) -> Result<(), SPVError> {
        if let Some(tip) = header_store.fetch_tip()? {
            let mut h = Arc::new(tip);
            while let Some(stored) = header_store.fetch(&h)? {
                self.trunk.push(h.clone());
                self.headers.insert(h, stored.clone());
                if stored.header.prev_blockhash != Sha256dHash::default() {
                    h = Arc::new(stored.header.prev_blockhash);
                } else {
                    break;
                }
            }
            self.trunk.reverse();
        }
        Ok(())
    }

    /// iterate from id to genesis
    pub fn iter_to_genesis<'a> (&'a self, id: &Sha256dHash) -> HeaderIterator<'a> {
        return HeaderIterator::new(self, id)
    }

    pub fn iter_to_tip<'a> (&'a self, id: &Sha256dHash) -> TrunkIterator<'a> {
        return TrunkIterator::new(self, id)
    }

    // locator for getheaders message
    pub fn locator_hashes(&self) -> Vec<Sha256dHash> {
        let mut locator = vec!();
        let mut skip = 1;
        let mut count = 0;
        let mut s = 0;

        let iterator = self.trunk.iter().rev();
        for h in iterator {
            if s == 0 {
                locator.push(*h.clone());
                count += 1;
                s = skip;
                if count > 10 {
                    skip *= 2;
                }
            }
            s -= 1;
        }

        locator
    }
}

pub struct TrunkIterator<'a> {
    current: Option<usize>,
    cache: &'a HeaderCache
}

impl<'a> TrunkIterator<'a> {
    pub fn new (cache: &'a HeaderCache, current: &Sha256dHash) -> TrunkIterator<'a> {
        TrunkIterator { current: cache.trunk.iter().rposition(|s|{ **s == *current }), cache }
    }
}

impl<'a> Iterator for TrunkIterator<'a> {
    type Item = Sha256dHash;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if let Some(pos) = self.current {
            if pos < self.cache.trunk.len () - 1 {
                let s = *self.cache.trunk[pos+1];
                self.current = Some(pos+1);
                return Some(s);
            }
            else {
                self.current = None;
            }
        }
        None
    }
}

pub struct HeaderIterator<'a> {
    current: Sha256dHash,
    cache: &'a HeaderCache
}

impl<'a> HeaderIterator<'a> {
    pub fn new (cache: &'a HeaderCache, tip: &Sha256dHash) -> HeaderIterator<'a> {
        HeaderIterator { current: tip.clone(), cache }
    }
}

impl<'a> Iterator for HeaderIterator<'a> {
    type Item = Sha256dHash;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.current == Sha256dHash::default() {
            return None;
        }
        if let Some (filter) = self.cache.headers.get(&self.current) {
            let ret = self.current.clone();
            self.current = filter.header.prev_blockhash;
            return Some(ret)
        }
        return None;
    }
}