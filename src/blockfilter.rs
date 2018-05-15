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

use std::io;
use std::cmp;
use std::collections::HashSet;

use bitcoin::network::encodable::VarInt;
use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable};
use bitcoin::network::serialize::{RawEncoder, RawDecoder};
use bitcoin::util::hash::Sha256dHash;

use std::hash::Hasher;
use siphasher::sip::SipHasher;

const GOLOMB_RICE_PARAMETER: u8 = 20;

/// Read and match on a serialized Golomb Coded Set Filter
pub struct GCSFilterReader<'a> {
    filter: GCSFilter,
    reader: &'a mut io::Read,
    query: HashSet<u64>
}

impl<'a> GCSFilterReader<'a> {
    /// Create a new filter reader
    pub fn new (reader: &'a mut io::Read, block_hash: &Sha256dHash) -> Result<GCSFilterReader<'a>, io::Error> {
        let mut decoder = RawDecoder::new(reader);
        let n_elements: VarInt = ConsensusDecodable::consensus_decode(&mut decoder)
            .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))?;
        let block_hash_as_int = block_hash.into_le();
        Ok(GCSFilterReader {
            filter: GCSFilter::new(block_hash_as_int.0[0], block_hash_as_int.0[1], n_elements.0 as u32),
            reader: decoder.into_inner(),
            query: HashSet::new() })
    }

    /// add a patter later matched with match_any
    pub fn add_query_pattern (&mut self, element: &[u8]) {
        self.query.insert (self.filter.hash(element));
    }

    /// check if any patter matched
    pub fn match_any (&mut self) -> Result<bool, io::Error> {
        if self.filter.n_elements > 0 {
            // map hashes to [0, n_elements << grp]
            let mut mapped = Vec::new();
            mapped.reserve(self.query.len());
            for h in &self.query {
                mapped.push(self.filter.map_to_range(*h));
            }
            // sort
            mapped.sort();

            // find first match in two sorted arrays in one read pass
            let mut reader = BitStreamReader::new(self.reader);
            let mut data = self.filter.golomb_rice_decode(&mut reader)?;
            let mut remaining = self.filter.n_elements - 1;
            for p in mapped {
                loop {
                    if data == p {
                        return Ok(true);
                    } else if data < p {
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        }
                        else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        Ok(false)
    }
}

/// A Golomb Coded Set Filter writer
pub struct GCSFilterWriter<'a> {
    filter: GCSFilter,
    writer: &'a mut io::Write,
    elements: HashSet<u64>
}

impl<'a> GCSFilterWriter<'a> {
    /// Create a new filter writer
    pub fn new (writer: &'a mut io::Write, block_hash: &Sha256dHash) -> GCSFilterWriter<'a> {
        let block_hash_as_int = block_hash.into_le();
        GCSFilterWriter {
            filter: GCSFilter::new(block_hash_as_int.0[0], block_hash_as_int.0[1], 0), writer, elements: HashSet::new()
        }
    }

    /// add an element to the filter
    pub fn add_element (&mut self, element: &[u8]) {
        self.elements.insert (self.filter.hash(element));
    }

    /// Finish and flush final filter
    pub fn finish (&mut self) -> Result<usize, io::Error> {
        // write number of elements as varint
        let mut encoder = RawEncoder::new(io::Cursor::new(Vec::new()));
        self.filter.n_elements = self.elements.len() as u32;
        VarInt(self.elements.len() as u64).consensus_encode(&mut encoder).unwrap();
        let mut wrote = self.writer.write(encoder.into_inner().into_inner().as_slice())?;
        // map hashes to [0, n_elements << grp]
        let mut mapped = Vec::new();
        mapped.reserve(self.elements.len());
        for h in &self.elements {
            mapped.push(self.filter.map_to_range(*h));
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
    k1: u64, // sip hash key
    n_elements: u32  // number of elements in the filter
}

impl GCSFilter {
    /// Create a new filter
    pub fn new (k0: u64, k1: u64, n_elements: u32) -> GCSFilter {
        GCSFilter { k0, k1, n_elements }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode (&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
        let mut wrote = 0;
        let mut q = n >> GOLOMB_RICE_PARAMETER;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, GOLOMB_RICE_PARAMETER)?;
        Ok(wrote)
    }

    /// Golomb-Rice decode a number from a bit stream (Parameter 2^k)
    fn golomb_rice_decode (&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(GOLOMB_RICE_PARAMETER)?;
        return Ok((q << GOLOMB_RICE_PARAMETER) + r);
    }

    /// Hash an arbitary slice with siphash using parameters of this filter
    fn hash (&self, element: &[u8]) -> u64 {
        let mut hasher = SipHasher::new_with_keys(self.k0, self.k1);
        hasher.write(element);
        hasher.finish()
    }

    fn map_to_range (&self, hash: u64) -> u64 {
        (((hash as u128) * ((self.n_elements as u128) << GOLOMB_RICE_PARAMETER)) >> 64) as u64
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
    use super::*;
    use std::io::Cursor;
    use rand;
    use rand::Rng;

    #[test]
    fn test_filter () {
        let mut bytes = Vec::new();
        let mut rng = rand::thread_rng();
        let mut patterns = HashSet::new();
        for _ in 0..1000 {

            use std::mem::transmute;
            let bytes: [u8; 8] = unsafe { transmute(rng.next_u64().to_be()) };
            patterns.insert(bytes);
        }
        {
            let mut out = Cursor::new(&mut bytes);
            let mut writer = GCSFilterWriter::new(&mut out, &Sha256dHash::default());
            for p in &patterns {
                writer.add_element(p);
            }
            writer.finish().unwrap();
        }
        {
            let mut input = Cursor::new(&mut bytes);
            let mut reader = GCSFilterReader::new(&mut input, &Sha256dHash::default()).unwrap();
            let mut it = patterns.iter();
            for _ in 0..5 {
                reader.add_query_pattern(it.next().unwrap());
            }
            for _ in 0..100 {
                let mut p = it.next().unwrap().to_vec();
                p [0] = !p[0];
                reader.add_query_pattern(p.as_slice());
            }
            assert!(reader.match_any().unwrap());
        }
        {
            let mut input = Cursor::new(&mut bytes);
            let mut reader = GCSFilterReader::new(&mut input, &Sha256dHash::default()).unwrap();
            let mut it = patterns.iter();
            for _ in 0..100 {
                let mut p = it.next().unwrap().to_vec();
                p [0] = !p[0];
                reader.add_query_pattern(p.as_slice());
            }
            assert!(!reader.match_any().unwrap());
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
}