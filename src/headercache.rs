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
use chaindb::StoredHeader;
use error::MurmelError;
use std::{
    collections::HashMap,
    sync::Arc
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

    pub fn add_header_unchecked(&mut self, stored: &StoredHeader) {
        let id = Arc::new(stored.bitcoin_hash());
        self.headers.insert(id.clone(), stored.clone());
        self.trunk.push(id);
    }

    /// add a Bitcoin header
    pub fn add_header(&mut self, header: &BlockHeader) -> Result<Option<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>)>, MurmelError> {
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
                return Err(MurmelError::UnconnectedHeader);
            }
            // add  to tree
            return Ok(Some(self.add_header_to_tree(&previous, header)?));
        } else {
            // insert genesis
            let new_tip = Arc::new(header.bitcoin_hash());
            let stored = StoredHeader {
                header: header.clone(),
                height: 0,
                log2work: Self::log2(header.work())
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
    fn add_header_to_tree(&mut self, prev: &StoredHeader, next: &BlockHeader) -> Result<(StoredHeader, Option<Vec<Sha256dHash>>, Option<Vec<Sha256dHash>>), MurmelError> {
        const DIFFCHANGE_INTERVAL: u32 = 2016;
        const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
        const TARGET_BLOCK_SPACING: u32 = 600;

        let required_work =
        // Compute required difficulty if this is a diffchange block
            if (prev.height + 1) % DIFFCHANGE_INTERVAL == 0 {
                let timespan = {
                    // Scan back DIFFCHANGE_INTERVAL blocks
                    let mut scan = prev.clone();
                    if self.tip_hash() == Some(scan.header.prev_blockhash) {
                        scan = self.headers.get(&self.trunk[self.trunk.len() - DIFFCHANGE_INTERVAL as usize - 2]).unwrap().clone();
                    } else {
                        for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                            if let Some(header) = self.headers.get(&scan.header.prev_blockhash) {
                                scan = header.clone();
                            } else {
                                return Err(MurmelError::UnconnectedHeader);
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
                let mut scan = prev.clone();
                let mut height = prev.height + 1;
                let max_target = Self::max_target();
                while height % DIFFCHANGE_INTERVAL != 0 && scan.header.target() == max_target {
                    if let Some(header) = self.headers.get(&scan.header.prev_blockhash) {
                        scan = header.clone();
                        height = header.height;
                    } else {
                        return Err(MurmelError::UnconnectedHeader);
                    }
                }
                scan.header.target()
                // Otherwise just use the last block's difficulty
            } else {
                prev.header.target()
            };

        if next.spv_validate(&required_work).is_err() {
            return Err(MurmelError::SpvBadProofOfWork);
        }
        // POW is sufficient
        let stored = StoredHeader {
            header: next.clone(),
            height: prev.height + 1,
            log2work: Self::log2(next.work() + Self::exp2(prev.log2work))
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
                while self.pos_on_trunk(&forks_at).is_none() {
                    if let Some(h) = self.headers.get(&forks_at) {
                        forks_at = h.header.prev_blockhash;
                        path_to_new_tip.push(forks_at);
                    } else {
                        return Err(MurmelError::UnconnectedHeader);
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
                        return Err(MurmelError::UnconnectedHeader);
                    }
                    self.trunk.extend(path_to_new_tip.iter().map(|h| { Arc::new(*h) }));

                    return Ok((stored, Some(unwinds), Some(path_to_new_tip)));
                } else {
                    self.trunk.extend(path_to_new_tip.iter().map(|h| { Arc::new(*h) }));

                    return Ok((stored, None, Some(path_to_new_tip)));
                }
            } else {
                return Ok((stored, None, None));
            }
        } else {
            return Err(MurmelError::NoTip);
        }
    }

    /// position on trunk (chain with most work from genesis to tip)
    pub fn pos_on_trunk(&self, hash: &Sha256dHash) -> Option<u32> {
        self.trunk.iter().rev().position(|e| { **e == *hash }).map(|p| (self.trunk.len() - p - 1) as u32)
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

    pub fn get_header_for_height(&self, height: u32) -> Option<StoredHeader> {
        if height < self.trunk.len() as u32 {
            self.headers.get(&self.trunk[height as usize]).cloned()
        }
        else {
            None
        }
    }

    pub fn iter_trunk<'a> (&'a self, from: u32) -> Box<Iterator<Item=&'a StoredHeader> +'a> {
        Box::new(self.trunk.iter().skip(from as usize).map(move |a| self.headers.get(&*a).unwrap()))
    }

    pub fn iter_trunk_rev<'a> (&'a self, from: Option<u32>) -> Box<Iterator<Item=&'a StoredHeader> +'a> {
        let len = self.trunk.len();
        if let Some(from) = from {
            Box::new(self.trunk.iter().rev().skip(len - from as usize).map(move |a| self.headers.get(&*a).unwrap()))
        }
        else {
            Box::new(self.trunk.iter().rev().map(move |a| self.headers.get(&*a).unwrap()))
        }
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
