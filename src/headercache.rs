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
use headerstore::StoredHeader;
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

    pub fn clear(&mut self) {
        self.headers.clear();
        self.trunk.truncate(0);
    }

    pub fn add_header_unchecked (&mut self, stored: &StoredHeader) {
        let id = Arc::new(stored.bitcoin_hash());
        self.headers.insert (id.clone(), stored.clone());
        self.trunk.push(id);
    }


    /// add a Bitcoin header
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, SPVError> {
        if self.headers.get(&header.bitcoin_hash()).is_some() {
            // ignore already known header
            return Ok(None);
        }
        if header.prev_blockhash != Sha256dHash::default() {
            // regular update
            let previous;
            if let Some(prev) = self.headers.get(&header.prev_blockhash) {
                previous = prev.clone();
            } else {
                // reject unconnected
                return Err(SPVError::UnconnectedHeader);
            }
            // add  to tree
            return Ok(Some(self.add_header_to_tree(&previous, header)?));
        } else {
            // insert genesis
            let new_tip = Arc::new(header.bitcoin_hash());
            let stored = StoredHeader {
                header: header.clone(),
                height: 0,
                log2work: Self::log2(header.work()),
            };
            self.trunk.push(new_tip.clone());
            self.headers.insert(new_tip.clone(), stored.clone());
            return Ok(Some((stored, None, Some(vec!(*new_tip)))));
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

    // add header to tree, return stored, optional list of unwinds, optional list of extensions
    fn add_header_to_tree(&mut self, prev: &StoredHeader, next: &BlockHeader) -> Result<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>), SPVError> {
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
        // POW is sufficient
        let stored = StoredHeader {
            header: next.clone(),
            height: prev.height + 1,
            log2work: Self::log2(next.work() + Self::exp2(prev.log2work)),
        };
        let next_hash = Arc::new(next.bitcoin_hash());

        // store header in cache
        self.headers.insert(next_hash.clone(), stored.clone());

        if let Some(tip) = self.tip() {
            if tip.log2work < stored.log2work {
                // higher POW than previous tip

                // compute path to new tip
                let mut forks_at = next.prev_blockhash;
                let mut path_to_new_tip = Vec::new();
                while !self.is_on_trunk(&forks_at) {
                    if let Some(h) = self.headers.get(&forks_at) {
                        forks_at = h.header.prev_blockhash;
                        path_to_new_tip.push(forks_at);
                    } else {
                        return Err(SPVError::UnconnectedHeader);
                    }
                }
                path_to_new_tip.reverse();
                path_to_new_tip.push(*next_hash);


                // compute list of headers no longer on trunk
                if forks_at != next.prev_blockhash {
                    let mut unwinds = Vec::new();

                    if let Some(pos) = self.trunk.iter().rposition(|h| { **h == forks_at }) {
                        if pos < self.trunk.len() - 1 {
                            // store and cut headers that are no longer on trunk
                            unwinds.extend(self.trunk[pos + 1..].iter().rev().map(|h| **h));
                            self.trunk.truncate(pos + 1);
                        }
                    } else {
                        return Err(SPVError::UnconnectedHeader);
                    }
                    self.trunk.extend(path_to_new_tip.iter().map(|h| {Arc::new(*h)}));

                    return Ok((stored, Some(unwinds), Some(path_to_new_tip)));
                }
                else {
                    self.trunk.extend(path_to_new_tip.iter().map(|h| {Arc::new(*h)}));

                    return Ok((stored, None, Some(path_to_new_tip)));
                }

            } else {
                return Ok((stored, None, None));
            }
        } else {
            return Err(SPVError::NoTip);
        }
    }

    /// is the hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk(&self, hash: &Sha256dHash) -> bool {
        self.trunk.iter().rposition(|e| { **e == *hash }).is_some()
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

    /// taken from an early rust-bitcoin by Andrew Poelstra:
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