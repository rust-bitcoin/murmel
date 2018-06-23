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
//! # BIP158 Compact Block Filters for Light Clients
//!
//! Implements a structure for compact filters on block data, for use in the BIP 157 light client protocol.
//! The filter construction proposed is an alternative to Bloom filters, as used in BIP 37,
//! that minimizes filter size by using Golomb-Rice coding for compression.
//!

use bitcoin;
use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use bitcoin::network::encodable::VarInt;
use bitcoin::network::serialize::{RawDecoder, RawEncoder};
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;
use siphasher::sip::SipHasher;
use std::cmp;
use std::collections::HashSet;
use std::hash::Hasher;
use std::io;

const P: u8 = 19;
const M: u64 = 784931;

/// Compiles and writes a block filter
pub struct BlockFilterWriter<'a> {
    block: &'a Block,
    writer: GCSFilterWriter<'a>
}

impl <'a> BlockFilterWriter<'a> {
    /// Create a block filter writer
    pub fn new (writer: &'a mut io::Write, block: &'a Block) -> BlockFilterWriter<'a> {
        let block_hash_as_int = block.bitcoin_hash().into_le();
        let writer = GCSFilterWriter::new(writer, block_hash_as_int.0[0], block_hash_as_int.0[1]);
        BlockFilterWriter { block, writer }
    }

    /// Add consumed inputs of the block
    pub fn add_inputs (&mut self) -> Result<(), io::Error> {
        for transaction in &self.block.txdata {
            // if not coin base
            if !transaction.is_coin_base() {
                for input in &transaction.input {
                    let mut outpoint =  encode (&input.prev_hash)?;
                    let serialized_previndex = encode(&input.prev_index)?;
                    outpoint.extend(serialized_previndex);

                    self.writer.add_element(outpoint.as_slice());
                }
            }
        }
        Ok(())
    }

    /// Add output scripts of the block - excluding OP_RETURN scripts
    pub fn add_output_scripts (&mut self) -> Result<(), io::Error> {
        for transaction in &self.block.txdata {
            for output in &transaction.output {
                let data = output.script_pubkey.data();
                //if data.len() > 0 && data[0] != bitcoin::blockdata::opcodes::All::OP_RETURN as u8 {
                    self.writer.add_element(data.as_slice());
                //}
            }
        }
        Ok(())
    }

    /// Add consumed output scripts of a block to filter
    pub fn add_consumed_scripts (&mut self, tx_accessor: impl TxAccessor) -> Result<(), io::Error> {
        for transaction in &self.block.txdata {
            if !transaction.is_coin_base() {
                for input in &transaction.input {
                    let tx = tx_accessor.get(&input.prev_hash)?;
                    self.add_element(tx.output[input.prev_index as usize].script_pubkey.data().as_slice())?;
                }
            }
        }
        Ok(())
    }

    /// add an arbitary element
    pub fn add_element (&mut self, element: &[u8]) -> Result<(), io::Error> {
        self.writer.add_element(element);
        Ok(())
    }

    /// compile a filter useful for wallets
    pub fn add_wallet_filter (&mut self, tx_accessor: impl TxAccessor) -> Result<(), io::Error> {
        self.add_inputs()?;
        self.add_consumed_scripts(tx_accessor)
    }

    /// compile basic filter as of BIP158
    pub fn basic_filter (&mut self) -> Result<(), io::Error> {
        self.add_inputs()?;
        self.add_output_scripts()
    }

    /// Write block filter
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        self.writer.finish()
    }
}

pub trait TxAccessor {
    fn get (&self, txid: &Sha256dHash) -> Result<Transaction, io::Error>;
}

fn encode<T: ? Sized>(data: &T) -> Result<Vec<u8>, io::Error>
    where T: ConsensusEncodable<RawEncoder<io::Cursor<Vec<u8>>>> {
    Ok(serialize(data)
        .map_err(|_| { io::Error::new(io::ErrorKind::InvalidData, "serialization error") })?)
}

fn serialize<T: ?Sized>(data: &T) -> Result<Vec<u8>, bitcoin::util::Error>
    where T: ConsensusEncodable<RawEncoder<io::Cursor<Vec<u8>>>>,
{
    let mut encoder = RawEncoder::new(io::Cursor::new(vec![]));
    data.consensus_encode(&mut encoder)?;
    Ok(encoder.into_inner().into_inner())
}

/// Reads and interpret a block filter
pub struct BlockFilterReader {
    reader: GCSFilterReader
}

impl BlockFilterReader {
    /// Create a block filter reader
    pub fn new (block_hash: &Sha256dHash) -> Result<BlockFilterReader, io::Error> {
        let block_hash_as_int = block_hash.into_le();
        Ok(BlockFilterReader {
            reader: GCSFilterReader::new( block_hash_as_int.0[0], block_hash_as_int.0[1])?
        })
    }

    /// add a query pattern
    pub fn add_query_pattern (&mut self, element: &[u8]) {
        self.reader.add_query_pattern (element);
    }

    /// match any previously added query pattern
    pub fn match_any (&mut self, reader: &mut io::Read) -> Result<bool, io::Error> {
        self.reader.match_any(reader)
    }
}


struct GCSFilterReader {
    filter: GCSFilter,
    query: HashSet<u64>
}

impl GCSFilterReader {
    fn new (k0: u64, k1: u64) -> Result<GCSFilterReader, io::Error> {
        Ok(GCSFilterReader {
            filter: GCSFilter::new(k0, k1),
            query: HashSet::new() })
    }

    fn add_query_pattern (&mut self, element: &[u8]) {
        self.query.insert (self.filter.hash(element));
    }

    fn match_any (&mut self, reader: &mut io::Read) -> Result<bool, io::Error> {
        let mut decoder = RawDecoder::new(reader);
        let n_elements: VarInt = ConsensusDecodable::consensus_decode(&mut decoder)
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))?;
        let ref mut reader = decoder.into_inner();
        if n_elements.0 == 0 {
            return Ok(false)
        }
        // map hashes to [0, n_elements << grp]
        let mut mapped = Vec::new();
        mapped.reserve(self.query.len());
        let nm = n_elements.0 * M;
        for h in &self.query {
            mapped.push(map_to_range(*h, nm));
        }
        // sort
        mapped.sort();

        // find first match in two sorted arrays in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                if data == p {
                    return Ok(true);
                } else if data < p {
                    if remaining > 0 {
                        data += self.filter.golomb_rice_decode(&mut reader)?;
                        remaining -= 1;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        Ok(false)
    }
}

// fast reduction of hash to [0, nm) range
fn map_to_range (hash: u64, nm: u64) -> u64 {
    ((hash as u128 * nm as u128) >> 64) as u64
}

struct GCSFilterWriter<'a> {
    filter: GCSFilter,
    writer: &'a mut io::Write,
    elements: HashSet<u64>
}

impl<'a> GCSFilterWriter<'a> {
    fn new (writer: &'a mut io::Write, k0: u64, k1: u64) -> GCSFilterWriter<'a> {
        GCSFilterWriter {
            filter: GCSFilter::new(k0, k1), writer, elements: HashSet::new()
        }
    }

    fn add_element (&mut self, element: &[u8]) {
        self.elements.insert (self.filter.hash(element));
    }

    fn finish (&mut self) -> Result<usize, io::Error> {
        // write number of elements as varint
        let mut encoder = RawEncoder::new(io::Cursor::new(Vec::new()));
        VarInt(self.elements.len() as u64).consensus_encode(&mut encoder).unwrap();
        let mut wrote = self.writer.write(encoder.into_inner().into_inner().as_slice())?;
        // map hashes to [0, n_elements * M)
        let mut mapped = Vec::new();
        let n = self.elements.len();
        mapped.reserve(n);
        let nm = n as u64 * M;
        for h in &self.elements {
            mapped.push(map_to_range(*h, nm));
        }
        // sort
        mapped.sort();
        // write out deltas of sorted values into a Golonb-Rice coded bit stream
        let mut writer = BitStreamWriter::new(self.writer);
        let mut last = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - last)?;
            last = data;
        }
        wrote += writer.flush()?;
        Ok(wrote)
    }
}

/// Golomb Coded Set Filter
struct GCSFilter {
    k0: u64, // sip hash key
    k1: u64 // sip hash key
}

impl GCSFilter {
    /// Create a new filter
    fn new (k0: u64, k1: u64) -> GCSFilter {
        GCSFilter { k0, k1 }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode (&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
        let mut wrote = 0;
        let mut q = n >> P;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, P)?;
        Ok(wrote)
    }

    /// Golomb-Rice decode a number from a bit stream (Parameter 2^k)
    fn golomb_rice_decode (&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(P)?;
        return Ok((q << P) + r);
    }

    /// Hash an arbitary slice with siphash using parameters of this filter
    fn hash (&self, element: &[u8]) -> u64 {
        let mut hasher = SipHasher::new_with_keys(self.k0, self.k1);
        hasher.write(element);
        hasher.finish()
    }
}

/// Bitwise stream reader
struct BitStreamReader<'a> {
    buffer: [u8;1],
    offset: u8,
    reader: &'a mut io::Read
}

impl<'a> BitStreamReader<'a> {
    /// Create a new BitStreamReader that reads bitwise from a given reader
    pub fn new (reader: &'a mut io::Read) -> BitStreamReader {
        BitStreamReader {
            buffer: [0u8],
            reader: reader,
            offset: 8
        }
    }

    /// Read nbit bits
    pub fn read (&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(io::ErrorKind::Other, "can not read more then 64 bits at once"));
        }
        let mut data = 0u64;
        while nbits > 0 {
            if self.offset == 8 {
                let read = self.reader.read(&mut self.buffer)?;
                if read == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"));
                }
                self.offset = 0;
            }
            let bits = cmp::min(8 - self.offset, nbits);
            data <<= bits;
            data |= ((self.buffer [0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer
struct BitStreamWriter<'a> {
    buffer: [u8;1],
    offset: u8,
    writer: &'a mut io::Write
}

impl<'a> BitStreamWriter<'a> {
    /// Create a new BitStreamWriter that writes bitwise to a given writer
    pub fn new (writer: &'a mut io::Write) -> BitStreamWriter {
        BitStreamWriter {
            buffer: [0u8],
            writer: writer,
            offset: 0
        }
    }

    /// Write nbits bits from data
    pub fn write (&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(io::ErrorKind::Other, "can not read more then 64 bits at once"));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer [0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written
    pub fn flush (&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write(&self.buffer)?;
            self.buffer [0] = 0u8;
            self.offset = 0;
            Ok(1)
        }
        else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod test {
    use blockfilter::test::rustc_serialize::json::Json;
    use rand;
    use rand::Rng;
    use std::fs::File;
    use std::io::Cursor;
    use std::io::Read;
    use std::path::PathBuf;
    use std::collections::HashMap;
    use super::*;

    extern crate rustc_serialize;

    extern crate hex;

    fn decode<T: ? Sized>(data: Vec<u8>) -> Result<T, io::Error>
        where T: ConsensusDecodable<RawDecoder<Cursor<Vec<u8>>>> {
        let mut decoder: RawDecoder<Cursor<Vec<u8>>> = RawDecoder::new(Cursor::new(data));
        Ok(ConsensusDecodable::consensus_decode(&mut decoder)
            .map_err(|_| { io::Error::new(io::ErrorKind::InvalidData, "serialization error") })?)
    }

    #[test]
    fn test_blockfilters () {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("tests/blockfilters.json");
        let mut file = File::open(d).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();

        let json = Json::from_str(&data).unwrap();
        let blocks = json[0].as_array().unwrap();
        let txs = json[1].as_array().unwrap();
        for t in 1..8 {
            let mut txmap = HashMap::new();
            let test_case = blocks [t].as_array().unwrap();
            let block_hash = Sha256dHash::from_hex(test_case [1].as_string().unwrap()).unwrap();
            let previous_header_hash = Sha256dHash::from_hex(test_case [3].as_string().unwrap()).unwrap();
            let header_hash = Sha256dHash::from_hex(test_case[5].as_string().unwrap()).unwrap();
            let block :Block = decode (hex::decode(test_case[2].as_string().unwrap()).unwrap()).unwrap();
            assert_eq!(block.bitcoin_hash(), block_hash);

            for tx in &block.txdata {
                txmap.insert(tx.txid(), tx.clone());
            }
            for i in 1 .. 8 {
                let line = txs[i].as_array().unwrap();
                let tx: Transaction = decode(hex::decode(line[1].as_string().unwrap()).unwrap()).unwrap();
                assert_eq!(tx.txid().to_string(), line[0].as_string().unwrap());
                txmap.insert(tx.txid(), tx);
            }

            let basic_filter = hex::decode(test_case[4].as_string().unwrap()).unwrap();
            let mut constructed_basic = Cursor::new(Vec::new());
            {
                let mut writer = BlockFilterWriter::new(&mut constructed_basic, &block);
                writer.basic_filter().unwrap();
                writer.finish().unwrap();
            }

            let filter = constructed_basic.into_inner();
            assert_eq!(basic_filter, filter);
            let filter_hash = Sha256dHash::from_data(filter.as_slice());
            let mut header_data = [0u8; 64];
            header_data[0..32].copy_from_slice(&filter_hash.data()[0..32]);
            header_data[32..64].copy_from_slice(&previous_header_hash.data()[0..32]);
            let filter_header_hash = Sha256dHash::from_data(&header_data);
            assert_eq!(filter_header_hash, header_hash);
        }
    }

    #[test]
    fn test_filter () {
        let mut bytes = Vec::new();
        let mut rng = rand::thread_rng();
        let mut patterns = HashSet::new();
        for _ in 0..1000 {
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            patterns.insert(bytes);
        }
        {
            let mut out = Cursor::new(&mut bytes);
            let mut writer = GCSFilterWriter::new(&mut out, 0, 0);
            for p in &patterns {
                writer.add_element(p);
            }
            writer.finish().unwrap();
        }
        {
            let ref mut reader = GCSFilterReader::new(0, 0).unwrap();
            let mut it = patterns.iter();
            for _ in 0..5 {
                reader.add_query_pattern(it.next().unwrap());
            }
            for _ in 0..100 {
                let mut p = it.next().unwrap().to_vec();
                p [0] = !p[0];
                reader.add_query_pattern(p.as_slice());
            }
            let mut input = Cursor::new(&bytes);
            assert!(reader.match_any(&mut input).unwrap());
        }
        {
            let mut reader = GCSFilterReader::new(0, 0).unwrap();
            let mut it = patterns.iter();
            for _ in 0..100 {
                let mut p = it.next().unwrap().to_vec();
                p [0] = !p[0];
                reader.add_query_pattern(p.as_slice());
            }
            let mut input = Cursor::new(&bytes);
            assert!(!reader.match_any(&mut input).unwrap());
        }
    }

    #[test]
    fn test_bit_stream () {
        let mut bytes = Vec::new();
        {
            let mut out = Cursor::new(&mut bytes);
            let mut writer = BitStreamWriter::new(&mut out);
            writer.write(0, 1).unwrap(); // 0
            writer.write(2, 2).unwrap(); // 10
            writer.write(6, 3).unwrap(); // 110
            writer.write(11, 4).unwrap(); // 1011
            writer.write(1, 5).unwrap(); // 00001
            writer.write(32, 6).unwrap(); // 100000
            writer.write(7, 7).unwrap(); // 0000111
            writer.flush().unwrap();
        }
        assert_eq!("01011010110000110000000001110000", format!("{:08b}{:08b}{:08b}{:08b}",bytes[0],bytes[1],bytes[2],bytes[3]));
        {
            let mut input = Cursor::new(&mut bytes);
            let mut reader = BitStreamReader::new(&mut input);
            assert_eq!(reader.read(1).unwrap(), 0);
            assert_eq!(reader.read(2).unwrap(), 2);
            assert_eq!(reader.read(3).unwrap(), 6);
            assert_eq!(reader.read(4).unwrap(), 11);
            assert_eq!(reader.read(5).unwrap(), 1);
            assert_eq!(reader.read(6).unwrap(), 32);
            assert_eq!(reader.read(7).unwrap(), 7);
            // 4 bits remained
            assert!(reader.read(5).is_err());
        }
    }

    #[test]
    fn foo () {
        let block :Block = decode (hex::decode("0100000020782a005255b657696ea057d5b98f34defcf75196f64f6eeac8026c0000000041ba5afc532aae03151b8aa87b65e1594f97504a768e010c98c0add79216247186e7494dffff001d058dc2b60101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0486e7494d0151062f503253482fffffffff0100f2052a01000000232103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac00000000").unwrap()).unwrap();
        println!("{}", block.header.bitcoin_hash());
        for t in block.txdata {
            for i in t.input {
                println!("{}", i.prev_hash);
            }
        }
    }
}