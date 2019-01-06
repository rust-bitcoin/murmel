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
//! # store headers with hammersbald and maintain a cache
//!

use bitcoin:: {
    blockdata::{
        block::{BlockHeader}
    },
    consensus::{Decodable, Encodable},
    network::constants::Network,
    util:: {
        hash::{BitcoinHash, Sha256dHash},
        uint::Uint256
    },
    consensus::{
        encode,
        encode::{Encoder, Decoder}
    }
};

use error::SPVError;
use hammersbald:: {
    HammersbaldAPI,
    HammersbaldError,
    BitcoinAdaptor
};
use std:: {
    collections::HashMap,
    io::Cursor,
    sync::Arc,
    error::Error
};

/// Adapter for Hammersbald storing Bitcoin data
pub struct HeaderStore {
    hammersbald: BitcoinAdaptor,
    network: Network,
    headers: HashMap<Arc<Sha256dHash>, StoredHeader>,
    trunk: Vec<Arc<Sha256dHash>>
}

/// A header enriched with information about its position on the blockchain
#[derive(Clone)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// chain height
    pub height: u32,
    /// log2 of total work * LOGWORK_SCALE
    pub log2work: u64
}

const LOGWORK_SCALE:f64 = 10_000_000_000f64;

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
        self.log2work.consensus_encode(s)?;
        Ok(())
    }
}

// implement decoder. tedious just repeat the consensus_encode lines
impl<D: Decoder> Decodable<D> for StoredHeader {
    fn consensus_decode(d: &mut D) -> Result<StoredHeader, encode::Error> {
        Ok(StoredHeader {
            header: Decodable::consensus_decode(d)?,
            height: Decodable::consensus_decode(d)?,
            log2work: Decodable::consensus_decode(d)? })
    }
}


impl HeaderStore {
    /// create a new Bitcoin adapter wrapping Hammersbald
    pub fn new(hammersbald: Box<HammersbaldAPI>, network: Network) -> HeaderStore {
        HeaderStore { hammersbald: BitcoinAdaptor::new(hammersbald), network, headers: HashMap::new(), trunk: Vec::new() }
    }

    /// Insert a Bitcoin header
    pub fn insert_header (&mut self, header: &BlockHeader) -> Result<bool, SPVError> {
        if self.headers.get(&header.bitcoin_hash()).is_some() {
            return Ok(false)
        }
        let stored;
        if header.prev_blockhash != Sha256dHash::default() {
            let previous;
            if let Some(prev) = self.headers.get(&header.prev_blockhash) {
               previous = prev.clone();
            }
            else {
                return Err(SPVError::UnconnectedHeader);
            }
            stored = self.add_header_to_tree(&previous,header)?;
        }
        else {
            let new_tip = Arc::new(header.bitcoin_hash());
            self.store_tip(&*new_tip)?;
            stored = StoredHeader {
                header: header.clone(),
                height: 0,
                log2work: (Self::log2(header.work()) * LOGWORK_SCALE) as u64
            };
            self.trunk.push(new_tip.clone());
            self.headers.insert(new_tip.clone(), stored.clone());
        }
        self.hammersbald.put_hash_keyed(&stored)?;
        Ok(true)
    }

    fn log2(work: Uint256) -> f64 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(work.0[2] == 0 && work.0[3] == 0);
        ((work.0[0] as u128 + ((work.0[1] as u128) << 64)) as f64).log2()
    }

    fn exp2(n: f64) -> Uint256 {
        // we will have u256 faster in Rust than 2^128 total work in Bitcoin
        assert!(n < 128.0);
        let e:u128 = n.exp2() as u128;
        let mut b = [0u64;4];
        b[0] = e as u64;
        b[1] = (e >> 64) as u64;
        Uint256(b)
    }

    fn max_target() -> Uint256 {
        Uint256::from_u64(0xFFFF).unwrap() << 208
    }

    /// POW comments and code based on a work by Andrew Poelstra
    fn add_header_to_tree(&mut self, prev: &StoredHeader, next: &BlockHeader) -> Result<StoredHeader, SPVError> {

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
                        scan = self.headers.get(&self.trunk [self.trunk.len() - DIFFCHANGE_INTERVAL as usize - 2]).unwrap();
                    }
                    else {
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
                prev.header.time > prev.header.time + 2*TARGET_BLOCK_SPACING {
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
                    if let Some(header)  = self.headers.get(&scan.header.prev_blockhash) {
                        scan = header;
                        height = header.height;
                    }
                    else {
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
            log2work: (Self::log2(next.work() + Self::exp2(prev.log2work as f64 / LOGWORK_SCALE)) * LOGWORK_SCALE) as u64
        };
        let next_hash = Arc::new(next.bitcoin_hash());

        self.headers.insert(next_hash.clone(), stored.clone());

        if let Some(tip) = self.tip() {
            if tip.log2work < stored.log2work {

                self.store_tip(&*next_hash.clone())?;

                let mut ph = *next_hash.clone();
                while !self.is_on_trunk(&ph) {
                    if let Some(h) = self.headers.get(&ph) {
                        ph = h.header.prev_blockhash;
                    }
                    else {
                        return Err(SPVError::UnconnectedHeader);
                    }
                }
                if let Some(pos) = self.trunk.iter().rposition(|h| {**h == ph}) {
                    if pos < self.trunk.len() - 1 {
                        self.trunk.truncate(pos + 1);
                    }
                }
                else {
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
                        }
                        else {
                            return Err(SPVError::UnconnectedHeader);
                        }
                    }
                }
                for h in new_trunk.iter().rev() {
                    self.trunk.push(h.clone());
                }
            }
            else {
                self.trunk.push(next_hash);
            }
        }
        else {
            return Err(SPVError::NoTip)
        }
        Ok(stored)
    }

    /// is the given hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk (&self, hash: &Sha256dHash) -> bool {
        self.trunk.iter().rposition(|e| { **e == *hash }).is_some()
    }

    /// retrieve the id of the block/header with most work
    pub fn tip (&self) -> Option<StoredHeader> {
        if let Some(id) = self.tip_hash() {
            return self.get_header(&id)
        }
        None
    }

    pub fn tip_hash (&self) -> Option<Sha256dHash> {
        if let Some(tip) = self.trunk.last() {
            return Some(**tip);
        }
        None
    }

    fn store_tip(&mut self, tip: &Sha256dHash) -> Result<(), SPVError> {
        self.hammersbald.put_keyed(&Sha256dHash::default().to_bytes()[..], &tip.to_bytes()[..])?;
        Ok(())
    }

    fn read_tip_hash(&self) -> Result<Option<Sha256dHash>, SPVError> {
        if let Some((_, h)) = self.hammersbald.get_keyed(&Sha256dHash::default().to_bytes()[..])? {
            return Ok(Some(Sha256dHash::from(h.as_slice())))
        }
        Ok(None)
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
    pub fn get_header (&self, id: &Sha256dHash)  -> Option<StoredHeader> {
        if let Some(header) = self.headers.get(id) {
            return Some(header.clone());
        }
        None
    }

    /// Fetch a header by its id from hammersbald
    fn fetch_header (&self, id: &Sha256dHash)  -> Result<Option<StoredHeader>, Box<Error>> {
        if let Some((_,stored)) = self.hammersbald.get_hash_keyed::<StoredHeader>(id)? {
            return Ok(Some(stored));
        }
        Ok(None)
    }

    /// initialize cache
    pub fn init_cache (&mut self, genesis: BlockHeader) -> Result<(), SPVError> {
        if let Some(tip) = self.read_tip_hash()? {
            let mut h = tip;
            while let Some(stored) = self.fetch_header(&h)? {
                let sh = Arc::new(stored.header.bitcoin_hash());
                self.trunk.push(sh.clone());
                self.headers.insert(sh, stored.clone());
                if stored.header.prev_blockhash != Sha256dHash::default() {
                    h = stored.header.prev_blockhash;
                }
                else {
                    break;
                }
            }
            self.trunk.reverse();
        }
        else {
            self.insert_header(&genesis)?;
        }
        Ok(())
    }

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

    /// shutdown hammersbald
    #[allow(unused)]
    pub fn shutdown (&mut self) {
        self.hammersbald.shutdown()
    }

    /// batch hammersbald
    pub fn batch (&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.batch()
    }
}
