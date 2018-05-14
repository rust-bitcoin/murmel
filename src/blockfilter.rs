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
use bitcoin::network::encodable::ConsensusEncodable;
use bitcoin::network::serialize::RawEncoder;

use std::hash::Hasher;
use siphasher::sip::SipHasher;

/// Golomb Coded Set Filter
pub struct GCSFilter {
    sip_hash_k0: u64, // sip hash key 0
    sip_hash_k1: u64, // sip hash key 1
    grp: u8,  // Golomb=Rice parameter (Golomb parameter = 2^p)
    n_elements: u32  // number of elements in the filter
}

impl GCSFilter {
    /// Create a new filter
    pub fn new (sip_hash_k0: u64, sip_hash_k1: u64, p: u8) -> GCSFilter {
        GCSFilter { sip_hash_k0, sip_hash_k1, grp: p, n_elements: 0 }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode (&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
        let mut wrote = 0;
        let mut q = n >> self.grp;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, self.grp)?;
        Ok(wrote)
    }

    /// Golomb-Rice decode a number from a bit stream (Parameter 2^k)
    fn golomb_rice_decode (&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(self.grp)?;
        return Ok((q << self.grp) + r);
    }

    fn hash (&self, element: &[u8]) -> u64 {
        let mut hasher = SipHasher::new_with_keys(self.sip_hash_k0, self.sip_hash_k1);
        hasher.write(element);
        hasher.finish()
    }

    fn map_to_range (&self, hash: u64) -> u64 {
        (((hash as u128) * (self.n_elements << self.grp) as u128) >> 64) as u64
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
    pub fn new (writer: &'a mut io::Write, sip_hash_k0: u64, sip_hash_k1: u64, p: u8) -> GCSFilterWriter<'a> {
        GCSFilterWriter {
            filter: GCSFilter::new(sip_hash_k0, sip_hash_k1, p),
            writer: writer,
            elements: HashSet::new()
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
        let mut delta = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - delta)?;
            delta += data;
        }
        Ok(wrote)
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