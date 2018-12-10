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

use error::SPVError;

use hammersbald:: {
    api::{HammersbaldAPI, Hammersbald},
    pref::PRef,
    error::HammersbaldError,
    datafile::DagIterator,
    format::{Payload, Data}
};

use bitcoin:: {
    blockdata::{
        block::{BlockHeader, Block},
        transaction::Transaction,
        script::Script
    },
    util:: {
        hash::{Sha256dHash, BitcoinHash},
        uint::Uint256
    },
    consensus::{Decodable, Encodable},
    network::constants::Network
};

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use std:: {
    io::Cursor,
    error::Error,
    fmt
};

/// Adapter for Hammersbald storing Bitcoin data
pub struct Headers {
    hammersbald: Hammersbald,
    network: Network
}

/// Errors returned by this library
#[derive(Debug)]
pub enum HeadersError {
    /// attempt to insert an unconnected header
    Unconnected,
    /// chain tip is not set
    NoTip,
    /// parse error
    ParseError
}

impl Error for HeadersError {
    fn description(&self) -> &str {
        match self {
            HeadersError::Unconnected => "unconnected header",
            HeadersError::NoTip => "the chain has no tip",
            HeadersError::ParseError => "parse error"
        }
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

impl fmt::Display for HeadersError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HeadersError error: {} cause: {:?}", self.description(), self.cause())
    }
}

/// A header enriched with information about its position on the blockchain
#[derive(Clone)]
pub struct StoredHeader {
    /// header
    pub header: BlockHeader,
    /// reference to previous header
    pub previous_ref: PRef,
    /// chain height
    pub height: u32,
    /// total work
    pub total_work: Uint256,
    /// required work
    pub required_work: Uint256
}

impl Headers {
    /// create a new Bitcoin adapter wrapping Hammersbald
    pub fn new(hammersbald: Hammersbald, network: Network) -> Headers {
        Headers { hammersbald, network }
    }

    /// Insert a Bitcoin header
    pub fn insert_header (&mut self, header: &BlockHeader) -> Result<PRef, SPVError> {
        let mut referred = vec!();
        let stored;
        if header.prev_blockhash != Sha256dHash::default() {
            if let Some((ph, sh, r)) = self.hammersbald.get(&header.prev_blockhash.as_bytes()[..])? {
                if let Some(prev) = Self::parse_header(sh, r)? {
                    stored = self.add_header_to_tree(ph, &prev,header)?;
                    referred.push(ph);
                }
                else {
                    return Err(SPVError::Generic("unable to parse stored header".to_string()));
                }
            }
            else {
                return Err(SPVError::Generic("header is not connected to the chain".to_string()));
            }
        }
        else {
            let new_tip = header.bitcoin_hash();
            self.hammersbald.put(&Sha256dHash::default().to_bytes()[..], &new_tip.to_bytes()[..], &vec!())?;
            stored = StoredHeader {
                header: header.clone(),
                previous_ref: PRef::invalid(),
                height: 0,
                total_work: Uint256::from_u64(0).unwrap(),
                required_work: header.target()
            }
        }
        let key = &header.bitcoin_hash().to_bytes()[..];
        let mut serialized_header = Vec::new();
        serialized_header.extend(encode(&stored.header)?);
        serialized_header.write_u24::<BigEndian>(stored.height)?; // height
        serialized_header.write_u48::<BigEndian>(PRef::invalid().as_u64())?; // no transactions
        for n in stored.required_work.0.iter() {
            serialized_header.write_u64::<BigEndian>(*n)?;
        }
        for n in stored.total_work.0.iter() {
            serialized_header.write_u64::<BigEndian>(*n)?;
        }
        Ok(self.hammersbald.put(&key[..], serialized_header.as_slice(), &referred)?)
    }

    fn max_target() -> Uint256 {
        Uint256::from_u64(0xFFFF).unwrap() << 208
    }

    /// POW comments and code based on a work by Andrew Poelstra
    fn add_header_to_tree(&mut self, prev_ref: PRef, prev: &StoredHeader, next: &BlockHeader) -> Result<StoredHeader, SPVError> {

        const DIFFCHANGE_INTERVAL: u32 = 2016;
        const DIFFCHANGE_TIMESPAN: u32 = 14 * 24 * 3600;
        const TARGET_BLOCK_SPACING: u32 = 600;

        let required_work =
        // Compute required difficulty if this is a diffchange block
            if (prev.height + 1) % DIFFCHANGE_INTERVAL == 0 {
                let timespan = {
                    // Scan back DIFFCHANGE_INTERVAL blocks
                    let mut scan = prev.clone();
                    for _ in 0..(DIFFCHANGE_INTERVAL - 1) {
                        if let Some(header)  = self.fetch_ref_header(scan.previous_ref)? {
                            scan = header;
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
                // Compactify (make expressible in the 8+24 nBits float format
                Self::satoshi_the_precision(target)
                // On non-diffchange blocks, Testnet has a rule that any 20-minute-long
                // block intervals result the difficulty
            } else if self.network == Network::Testnet &&
                prev.header.time > prev.header.time + 2*TARGET_BLOCK_SPACING {
                Self::max_target()
                // On the other hand, if we are in Testnet and the block interval is less
                // than 20 minutes, we need to scan backward to find a block for which the
                // previous rule did not apply, to find the "real" difficulty.
            } else if self.network == Network::Testnet {
                // Scan back DIFFCHANGE_INTERVAL blocks
                let mut scan = prev.clone();
                let mut height = prev.height + 1;
                while height % DIFFCHANGE_INTERVAL != 0 &&
                    scan.required_work == Self::max_target() {
                    if let Some(header)  = self.fetch_ref_header(scan.previous_ref)? {
                        scan = header.clone();
                        height = header.height;
                    }
                }
                scan.required_work
                // Otherwise just use the last block's difficulty
            } else {
                prev.required_work
            };
        let stored = StoredHeader {
            header: next.clone(),
            height: prev.height + 1,
            previous_ref: prev_ref,
            required_work,
            total_work: next.work() + prev.total_work
        };
        if stored.header.spv_validate(&stored.required_work).is_err() {
            return Err(SPVError::SpvBadProofOfWork);
        }
        if let Some(tip) = self.tip()? {
            if tip.total_work < stored.total_work {
                let new_tip = stored.header.bitcoin_hash();
                self.hammersbald.put(&Sha256dHash::default().to_bytes()[..], &new_tip.to_bytes()[..], &vec!())?;
            }
        }
        else {
            let new_tip = stored.header.bitcoin_hash();
            self.hammersbald.put(&Sha256dHash::default().to_bytes()[..], &new_tip.to_bytes()[..], &vec!())?;
        }
        Ok(stored)
    }

    /// is the given hash part of the trunk (chain from genesis to tip)
    pub fn is_on_trunk (&self, hash: &Sha256dHash) -> Result<bool, SPVError> {
        if let Some(mut tip) = self.tip()? {
            let mut th = tip.header.bitcoin_hash();
            while th != Sha256dHash::default() {
                if *hash == th {
                    return Ok(true);
                }
                if let Some(p) = self.fetch_header(&tip.header.prev_blockhash)? {
                    tip = p;
                    th = tip.header.bitcoin_hash();
                }
                else {
                    return Err(SPVError::Generic(format!("{} is not on the chain", hash)));
                }
            }
        }
        Ok(false)
    }

    /// retrieve the id of the block/header with most work
    pub fn tip (&self) -> Result<Option<StoredHeader>, SPVError> {
        if let Some((_, id, _)) = self.hammersbald.get(&Sha256dHash::default().to_bytes()[..])? {
            return Ok(self.fetch_header(&decode(id.as_slice())?)?);
        }
        Ok(None)
    }

    /// This function emulates the `GetCompact(SetCompact(n))` in the satoshi code,
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


    /// Fetch a header by its id
    pub fn fetch_header (&self, id: &Sha256dHash)  -> Result<Option<StoredHeader>, SPVError> {
        let key = &id.to_bytes()[..];
        if let Some((_,stored,referred)) = self.hammersbald.get(&key)? {
            return Self::parse_header(stored, referred);
        }
        Ok(None)
    }

    /// Fetsch a header by its position
    pub fn fetch_ref_header(&self, pref: PRef) -> Result<Option<StoredHeader>, SPVError> {
        let (_, stored, referred) = self.hammersbald.get_referred(pref)?;
        return Self::parse_header(stored, referred);
    }

    fn parse_header(stored: Vec<u8>, referred: Vec<PRef>) -> Result<Option<StoredHeader>, SPVError> {
        let header = decode(&stored[0..80])?;
        let mut data = Cursor::new(&stored[80..]);
        let height = data.read_u24::<BigEndian>()?;
        PRef::from(data.read_u48::<BigEndian>()?); // do not care of transactions

        let previous_ref = if referred.len() > 0 { referred[0] } else { PRef::invalid() };
        let required_difficulty = Self::parse_u256(&mut data)?;
        let total_work = Self::parse_u256(&mut data)?;

        return Ok(Some(StoredHeader{header, height, previous_ref, total_work, required_work: required_difficulty }))
    }

    fn parse_u256(data: &mut Cursor<&[u8]>) -> Result<Uint256, SPVError> {
        let mut words = [0u64; 4];
        words[0] = data.read_u64::<BigEndian>()?;
        words[1] = data.read_u64::<BigEndian>()?;
        words[2] = data.read_u64::<BigEndian>()?;
        words[3] = data.read_u64::<BigEndian>()?;
        Ok(Uint256(words))
    }

    /// insert a block
    pub fn insert_block(&mut self, block: &Block) -> Result<PRef, SPVError> {
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
        serialized_block.write_u24::<BigEndian>(0)?; // height
        serialized_block.write_u48::<BigEndian>(stored_tx_offsets.as_u64())?;
        Ok(self.hammersbald.put(&key[..], serialized_block.as_slice(), &referred)?)
    }

    /// Fetch a block by its id
    pub fn fetch_block (&self, id: &Sha256dHash)  -> Result<Option<(Block, Vec<Vec<u8>>)>, Box<Error>> {
        let key = &id.as_bytes()[..];
        if let Some((_, stored, _)) = self.hammersbald.get(&key)? {
            let header = decode(&stored[0..80])?;
            let mut data = Cursor::new(&stored[80..]);
            let txdata_offset = PRef::from(data.read_u48::<BigEndian>()?);
            let mut txdata: Vec<Transaction> = Vec::new();
            if txdata_offset.is_valid() {
                let (_, _, txrefs) = self.hammersbald.get_referred(txdata_offset)?;
                for txref in &txrefs {
                    let (_, tx, _) = self.hammersbald.get_referred(*txref)?;
                    txdata.push(decode(tx.as_slice())?);
                }
            }
            let next = data.read_u32::<BigEndian>()?;
            let mut extension = Vec::new();
            for _ in 0..next {
                let pref = PRef::from(data.read_u48::<BigEndian>()?);
                let (_, e, _) = self.hammersbald.get_referred(pref)?;
                extension.push(e);
            }

            return Ok(Some((Block { header, txdata }, extension)))
        }
        Ok(None)
    }

    /// iterate over stored headers
    pub fn iter_headers<'s>(&'s self, tip: &Sha256dHash) -> Result<impl Iterator<Item=StoredHeader> +'s, SPVError> {
        if let Some((tipref, _, _)) = self.get(&tip.as_bytes()[..])? {
            return Ok(BitcoinHeaderScan { tip: tipref, hb: self })
        }
        return Err(SPVError::Generic("no tip".to_string()));
    }
}


struct BitcoinHeaderScan<'s> {
    tip: PRef,
    hb: &'s HammersbaldAPI
}

impl<'s> Iterator for BitcoinHeaderScan<'s> {
    type Item = StoredHeader;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.tip.is_valid() {
            if let Ok((_,data,referred)) = self.hb.get_referred(self.tip) {
                if referred.len() > 0 {
                    self.tip = referred[0];
                }
                    else {
                        self.tip = PRef::invalid();
                    }
                if let Ok(Some(result)) = Headers::parse_header(data, referred) {
                    return Some(result)
                }
            }
            return None;
        }
        None
    }
}

impl HammersbaldAPI for Headers {
    fn init(&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.init()
    }

    fn batch(&mut self) -> Result<(), HammersbaldError> {
        self.hammersbald.batch()
    }

    fn shutdown(&mut self) {
        self.hammersbald.shutdown()
    }

    fn put(&mut self, key: &[u8], data: &[u8], referred: &Vec<PRef>) -> Result<PRef, HammersbaldError> {
        self.hammersbald.put(key, data, &referred)
    }

    fn get(&self, key: &[u8]) -> Result<Option<(PRef, Vec<u8>, Vec<PRef>)>, HammersbaldError> {
        self.hammersbald.get(key)
    }

    fn put_referred(&mut self, data: &[u8], referred: &Vec<PRef>) -> Result<PRef, HammersbaldError> {
        self.hammersbald.put_referred(data, referred)
    }

    fn get_referred(&self, pref: PRef) -> Result<(Vec<u8>, Vec<u8>, Vec<PRef>), HammersbaldError> {
        self.hammersbald.get_referred(pref)
    }

    fn dag(&self, root: PRef) -> DagIterator {
        self.hammersbald.dag(root)
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

#[cfg(test)]
mod test {
    extern crate rand;
    extern crate hex;

    use hammersbald::transient::Transient;

    use hammersbald::api::HammersbaldFactory;
    use bitcoin::network::constants::Network;
    use bitcoin::blockdata::constants::genesis_block;

    use super::*;

    #[test]
    fn hashtest() {
        let mut db = Transient::new_db("first", 1, 1).unwrap();
        db.init().unwrap();
        let data = encode(&Sha256dHash::default()).unwrap();
        let key = encode(&Sha256dHash::default()).unwrap();
        let pref = db.put(&key[..], data.as_slice(), &vec!()).unwrap();
        assert_eq!(db.get(&key[..]).unwrap(), Some((pref, data, vec!())));
        db.shutdown();
    }

    #[test]
    fn header_test() {
        let mut db = Headers::new(
            Transient::new_db("first", 1, 1).unwrap(),
            Network::Bitcoin);

        db.init().unwrap();

        let genesis = genesis_block(Network::Bitcoin).header;

        db.insert_header(&genesis).unwrap();
        assert_eq!(genesis.bitcoin_hash(), db.tip().unwrap().unwrap().header.bitcoin_hash());

        let next: Block = decode(hex::decode("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e362990101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000".as_bytes()).unwrap().as_ref()).unwrap();
        db.insert_header(&next.header).unwrap();

        assert_eq!(next.bitcoin_hash(), db.tip().unwrap().unwrap().header.bitcoin_hash());
        db.batch().unwrap();
        db.shutdown();
    }
}