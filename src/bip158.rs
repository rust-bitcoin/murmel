// Rust Bitcoin Library
// Written in 2019 by
//   The rust-bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

// This module was largely copied from https://github.com/rust-bitcoin/murmel/blob/master/src/blockfilter.rs
// on 11. June 2019 which is licensed under Apache, that file specifically
// was written entirely by Tamas Blummer, who is re-licensing its contents here as CC0.

//!
//! # BIP158 Compact Block Filters for Light Clients
//!
//! Implements a structure for compact filters on block data, for use in the BIP 157 light client protocol.
//! The filter construction proposed is an alternative to Bloom filters, as used in BIP 37,
//! that minimizes filter size by using Golomb-Rice coding for compression.
//!
//!  USE :
//!   // create a block filter for a block (server side)
//!
//!   fn get_script_for_coin (coin: &OutPoint) -> Result<Script, BlockFilterError> {
//!     // get utxo ...
//!   }
//!
//!   let filter = BlockFilter::new_script_filter (&block, get_script_for_coin)?;
//!
//!   // or create a filter from known raw data
//!   let filter = BlockFilter::new(&block_hash, filter_type, content);
//!
//!   // read and evaluate a filter
//!
//!   let query: Iterator<Item=Script> = // .. some scripts you care about
//!   if filter.match_any (&mut query.map(|s| s.as_bytes())) {
//!     // get this block
//!   }
//!
//!

use std::{cmp, fmt, io};
use std::collections::HashSet;
use std::error;
use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::hash::Hasher;

use bitcoin_hashes::{Hash, sha256d};
use byteorder::{ByteOrder, LittleEndian};
use siphasher::sip128::SipHasher;

use bitcoin::{
    blockdata::{
        block::Block,
        script::Script,
        transaction::OutPoint
    },
    consensus::{
        {Decodable, Encodable},
        encode::VarInt
    },
    util::hash::BitcoinHash
};

/// BIP158 base filter type 0: input and output scripts
pub const SCRIPT_FILTER: u8 = 0;

/// Golomb encoding parameter as in BIP-158, see also https://gist.github.com/sipa/576d5f09c3b86c3b1b75598d799fc845
const P: u8 = 19;
const M: u64 = 784931;

/// Errors for blockfilter
#[derive(Debug)]
pub enum Error {
    /// missing UTXO, can not calculate script filter
    UtxoMissing(OutPoint),
    /// some IO error reading or writing binary serialization of the filter
    Io(io::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::UtxoMissing(_) => "unresolved UTXO",
            Error::Io(_) => "IO Error"
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::UtxoMissing(ref coin) => write!(f, "unresolved UTXO {}", coin),
            Error::Io(ref io) => write!(f, "{}", io)
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}


/// a computed or read block filter
pub struct BlockFilter {
    /// id of the block
    pub block_hash: sha256d::Hash,
    /// filte type (see SCRIPT_FILTER)
    pub filter_type: u8,
    /// Golomb encoded filter
    pub content: Vec<u8>,
    // a reader of the filter
    filter_reader: BlockFilterReader
}

impl BlockFilter {
    /// create a new filter from pre-computed data
    pub fn new (block_hash: sha256d::Hash, filter_type: u8, content: &[u8]) -> BlockFilter {
        let filter_reader = BlockFilterReader::new(&block_hash);
        BlockFilter { block_hash, filter_type, content: content.to_vec(), filter_reader }
    }

    /// Compute a SCRIPT_FILTER that contains spent and output scripts
    pub fn new_script_filter<M>(block: &Block, script_for_coin: M) -> Result<BlockFilter, Error>
        where M: Fn(&OutPoint) -> Result<Script, Error> {
        let mut out = Cursor::new(Vec::new());
        let mut writer = BlockFilterWriter::new(&mut out, block);
        writer.add_output_scripts();
        writer.add_input_scripts(script_for_coin)?;
        writer.finish()?;
        let block_hash = block.bitcoin_hash();
        let filter_reader = BlockFilterReader::new(&block_hash);
        Ok(BlockFilter { block_hash, filter_type: SCRIPT_FILTER, content: out.into_inner(), filter_reader })
    }

    /// match any query pattern
    pub fn match_any(&self, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        self.filter_reader.match_any(&mut Cursor::new(self.content.as_slice()), query)
    }

    /// match all query pattern
    pub fn match_all(&self, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        self.filter_reader.match_all(&mut Cursor::new(self.content.as_slice()), query)
    }
}

/// Compiles and writes a block filter
pub struct BlockFilterWriter<'a> {
    block: &'a Block,
    writer: GCSFilterWriter<'a>,
}

impl<'a> BlockFilterWriter<'a> {
    /// Create a block filter writer
    pub fn new(writer: &'a mut io::Write, block: &'a Block) -> BlockFilterWriter<'a> {
        let block_hash_as_int = block.bitcoin_hash().into_inner();
        let k0 = LittleEndian::read_u64(&block_hash_as_int[0..8]);
        let k1 = LittleEndian::read_u64(&block_hash_as_int[8..16]);
        let writer = GCSFilterWriter::new(writer, k0, k1);
        BlockFilterWriter { block, writer }
    }

    /// Add output scripts of the block - excluding OP_RETURN scripts
    pub fn add_output_scripts(&mut self) {
        for transaction in &self.block.txdata {
            for output in &transaction.output {
                if !output.script_pubkey.is_op_return() {
                    self.add_element(output.script_pubkey.as_bytes());
                }
            }
        }
    }

    /// Add consumed output scripts of a block to filter
    pub fn add_input_scripts<M>(&mut self, script_for_coin: M) -> Result<(), Error>
        where M: Fn(&OutPoint) -> Result<Script, Error> {
        for script in self.block.txdata.iter()
            .skip(1) // skip coinbase
            .flat_map(|t| t.input.iter().map(|i| &i.previous_output))
            .map(script_for_coin) {
            match script {
                Ok(script) => self.add_element(script.as_bytes()),
                Err(e) => return Err(e)
            }
        }
        Ok(())
    }

    /// Add arbitrary element to a filter
    pub fn add_element(&mut self, data: &[u8]) {
        self.writer.add_element(data);
    }

    /// Write block filter
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        self.writer.finish()
    }
}


/// Reads and interpret a block filter
pub struct BlockFilterReader {
    reader: GCSFilterReader
}

impl BlockFilterReader {
    /// Create a block filter reader
    pub fn new(block_hash: &sha256d::Hash) -> BlockFilterReader {
        let block_hash_as_int = block_hash.into_inner();
        let k0 = LittleEndian::read_u64(&block_hash_as_int[0..8]);
        let k1 = LittleEndian::read_u64(&block_hash_as_int[8..16]);
        BlockFilterReader { reader: GCSFilterReader::new(k0, k1) }
    }

    /// match any query pattern
    pub fn match_any(&self, reader: &mut io::Read, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        self.reader.match_any(reader, query)
    }

    /// match all query pattern
    pub fn match_all(&self, reader: &mut io::Read, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        self.reader.match_all(reader, query)
    }
}


struct GCSFilterReader {
    filter: GCSFilter
}

impl GCSFilterReader {
    fn new(k0: u64, k1: u64) -> GCSFilterReader {
        GCSFilterReader { filter: GCSFilter::new(k0, k1) }
    }

    fn match_any(&self, reader: &mut io::Read, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder)
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))?;
        let ref mut reader = decoder;
        if n_elements.0 == 0 {
            return Ok(false);
        }
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * M;
        let mut mapped = query.map(|e| map_to_range(self.filter.hash(e), nm)).collect::<Vec<_>>();
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
                        return Ok(false);
                    }
                } else {
                    break;
                }
            }
        }
        Ok(false)
    }

    fn match_all(&self, reader: &mut io::Read, query: &mut Iterator<Item=&[u8]>) -> Result<bool, io::Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder)
            .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF"))?;
        let ref mut reader = decoder;
        if n_elements.0 == 0 {
            return Ok(false);
        }
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * M;
        let mut mapped = query.map(|e| map_to_range(self.filter.hash(e), nm)).collect::<Vec<_>>();
        // sort
        mapped.sort();
        mapped.dedup();

        // figure if all mapped are there in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                if data == p {
                    break;
                } else if data < p {
                    if remaining > 0 {
                        data += self.filter.golomb_rice_decode(&mut reader)?;
                        remaining -= 1;
                    } else {
                        return Ok(false);
                    }
                } else {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

// fast reduction of hash to [0, nm) range
fn map_to_range(hash: u64, nm: u64) -> u64 {
    // Use this once we upgrade to rustc >= 1.26
    // ((hash as u128 * nm as u128) >> 64) as u64

    #[inline]
    fn l(n: u64) -> u64 { n & 0xffffffff }
    #[inline]
    fn h(n: u64) -> u64 { n >> 32 }

    let a = h(hash);
    let b = l(hash);
    let c = h(nm);
    let d = l(nm);

    a * c + h(a * d + c * b + h(b * d))
}

struct GCSFilterWriter<'a> {
    filter: GCSFilter,
    writer: &'a mut io::Write,
    elements: HashSet<Vec<u8>>,
}

impl<'a> GCSFilterWriter<'a> {
    fn new(writer: &'a mut io::Write, k0: u64, k1: u64) -> GCSFilterWriter<'a> {
        GCSFilterWriter {
            filter: GCSFilter::new(k0, k1),
            writer,
            elements: HashSet::new(),
        }
    }

    fn add_element(&mut self, element: &[u8]) {
        self.elements.insert(element.to_vec());
    }

    fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len() as u64 * M;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self.elements.iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm)).collect();
        mapped.sort();

        // write number of elements as varint
        let mut encoder = io::Cursor::new(Vec::new());
        VarInt(mapped.len() as u64).consensus_encode(&mut encoder).unwrap();
        let mut wrote = self.writer.write(encoder.into_inner().as_slice())?;

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
    k0: u64,
    // sip hash key
    k1: u64, // sip hash key
}

impl GCSFilter {
    /// Create a new filter
    fn new(k0: u64, k1: u64) -> GCSFilter {
        GCSFilter { k0, k1 }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode(&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
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
    fn golomb_rice_decode(&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(P)?;
        return Ok((q << P) + r);
    }

    /// Hash an arbitary slice with siphash using parameters of this filter
    fn hash(&self, element: &[u8]) -> u64 {
        let mut hasher = SipHasher::new_with_keys(self.k0, self.k1);
        hasher.write(element);
        hasher.finish()
    }
}

/// Bitwise stream reader
struct BitStreamReader<'a> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut io::Read,
}

impl<'a> BitStreamReader<'a> {
    /// Create a new BitStreamReader that reads bitwise from a given reader
    pub fn new(reader: &'a mut io::Read) -> BitStreamReader {
        BitStreamReader {
            buffer: [0u8],
            reader: reader,
            offset: 8,
        }
    }

    /// Read nbit bits
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
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
            data |= ((self.buffer[0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer
struct BitStreamWriter<'a> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut io::Write,
}

impl<'a> BitStreamWriter<'a> {
    /// Create a new BitStreamWriter that writes bitwise to a given writer
    pub fn new(writer: &'a mut io::Write) -> BitStreamWriter {
        BitStreamWriter {
            buffer: [0u8],
            writer: writer,
            offset: 0,
        }
    }

    /// Write nbits bits from data
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(io::ErrorKind::Other, "can not read more then 64 bits at once"));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashSet, HashMap};
    use std::io::Cursor;

    use bitcoin_hashes::hex::FromHex;

    use bitcoin::blockdata;
    use bitcoin::blockdata::transaction::OutPoint;

    use super::*;

    extern crate hex;

    fn decode<T: ?Sized>(data: Vec<u8>) -> Result<T, io::Error>
        where T: Decodable<Cursor<Vec<u8>>> {
        let mut decoder = Cursor::new(data);
        Ok(Decodable::consensus_decode(&mut decoder)
            .map_err(|_| { io::Error::new(io::ErrorKind::InvalidData, "serialization error") })?)
    }

    #[test]
    fn test_blockfilters() {
        let data = vec![
            vec![
                //vec!["Block Height,Block Hash,Block,Previous Basic Header,Basic Filter,Basic Header,Notes"],
                vec!["0", "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943", "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000", "0000000000000000000000000000000000000000000000000000000000000000", "019dfca8", "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750", "Genesis block"],
                vec!["1", "00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206", "0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b6720101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0420e7494d017f062f503253482fffffffff0100f2052a010000002321021aeaf2f8638a129a3156fbe7e5ef635226b0bafd495ff03afe2c843d7e3a4b51ac00000000", "21584579b7eb08997773e5aeff3a7f932700042d0ed2a6129012b7d7ae81b750", "015d5000", "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1", "Extended filter is empty"],
                vec!["2", "000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820", "0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d235340101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0432e7494d010e062f503253482fffffffff0100f2052a010000002321038a7f6ef1c8ca0c588aa53fa860128077c9e6c11e6830f4d7ee4e763a56b7718fac00000000", "d7bdac13a59d745b1add0d2ce852f1a0442e8945fc1bf3848d3cbffd88c24fe1", "0174a170", "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0", ""],
                vec!["3", "000000008b896e272758da5297bcd98fdc6d97c9b765ecec401e286dc1fdbe10", "0100000020782a005255b657696ea057d5b98f34defcf75196f64f6eeac8026c0000000041ba5afc532aae03151b8aa87b65e1594f97504a768e010c98c0add79216247186e7494dffff001d058dc2b60101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0486e7494d0151062f503253482fffffffff0100f2052a01000000232103f6d9ff4c12959445ca5549c811683bf9c88e637b222dd2e0311154c4c85cf423ac00000000", "186afd11ef2b5e7e3504f2e8cbf8df28a1fd251fe53d60dff8b1467d1b386cf0", "016cf7a0", "8d63aadf5ab7257cb6d2316a57b16f517bff1c6388f124ec4c04af1212729d2a", ""],
                vec!["926485", "000000000000015d6077a411a8f5cc95caf775ccf11c54e27df75ce58d187313", "0000002060bbab0edbf3ef8a49608ee326f8fd75c473b7e3982095e2d100000000000000c30134f8c9b6d2470488d7a67a888f6fa12f8692e0c3411fbfb92f0f68f67eedae03ca57ef13021acc22dc4105010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2f0315230e0004ae03ca57043e3d1e1d0c8796bf579aef0c0000000000122f4e696e6a61506f6f6c2f5345475749542fffffffff038427a112000000001976a914876fbb82ec05caa6af7a3b5e5a983aae6c6cc6d688ac0000000000000000266a24aa21a9ed5c748e121c0fe146d973a4ac26fa4a68b0549d46ee22d25f50a5e46fe1b377ee00000000000000002952534b424c4f434b3acd16772ad61a3c5f00287480b720f6035d5e54c9efc71be94bb5e3727f10909001200000000000000000000000000000000000000000000000000000000000000000000000000100000000010145310e878941a1b2bc2d33797ee4d89d95eaaf2e13488063a2aa9a74490f510a0100000023220020b6744de4f6ec63cc92f7c220cdefeeb1b1bed2b66c8e5706d80ec247d37e65a1ffffffff01002d3101000000001976a9143ebc40e411ed3c76f86711507ab952300890397288ac0400473044022001dd489a5d4e2fbd8a3ade27177f6b49296ba7695c40dbbe650ea83f106415fd02200b23a0602d8ff1bdf79dee118205fc7e9b40672bf31563e5741feb53fb86388501483045022100f88f040e90cc5dc6c6189d04718376ac19ed996bf9e4a3c29c3718d90ffd27180220761711f16c9e3a44f71aab55cbc0634907a1fa8bb635d971a9a01d368727bea10169522103b3623117e988b76aaabe3d63f56a4fc88b228a71e64c4cc551d1204822fe85cb2103dd823066e096f72ed617a41d3ca56717db335b1ea47a1b4c5c9dbdd0963acba621033d7c89bd9da29fa8d44db7906a9778b53121f72191184a9fee785c39180e4be153ae00000000010000000120925534261de4dcebb1ed5ab1b62bfe7a3ef968fb111dc2c910adfebc6e3bdf010000006b483045022100f50198f5ae66211a4f485190abe4dc7accdabe3bc214ebc9ea7069b97097d46e0220316a70a03014887086e335fc1b48358d46cd6bdc9af3b57c109c94af76fc915101210316cff587a01a2736d5e12e53551b18d73780b83c3bfb4fcf209c869b11b6415effffffff0220a10700000000001976a91450333046115eaa0ac9e0216565f945070e44573988ac2e7cd01a000000001976a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac00000000010000000203a25f58630d7a1ea52550365fd2156683f56daf6ca73a4b4bbd097e66516322010000006a47304402204efc3d70e4ca3049c2a425025edf22d5ca355f9ec899dbfbbeeb2268533a0f2b02204780d3739653035af4814ea52e1396d021953f948c29754edd0ee537364603dc012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff03a25f58630d7a1ea52550365fd2156683f56daf6ca73a4b4bbd097e66516322000000006a47304402202d96defdc5b4af71d6ba28c9a6042c2d5ee7bc6de565d4db84ef517445626e03022022da80320e9e489c8f41b74833dfb6a54a4eb5087cdb46eb663eef0b25caa526012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff0200e1f5050000000017a914b7e6f7ff8658b2d1fb107e3d7be7af4742e6b1b3876f88fc00000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac0000000001000000043ffd60d3818431c495b89be84afac205d5d1ed663009291c560758bbd0a66df5010000006b483045022100f344607de9df42049688dcae8ff1db34c0c7cd25ec05516e30d2bc8f12ac9b2f022060b648f6a21745ea6d9782e17bcc4277b5808326488a1f40d41e125879723d3a012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffffa5379401cce30f84731ef1ba65ce27edf2cc7ce57704507ebe8714aa16a96b92010000006a473044022020c37a63bf4d7f564c2192528709b6a38ab8271bd96898c6c2e335e5208661580220435c6f1ad4d9305d2c0a818b2feb5e45d443f2f162c0f61953a14d097fd07064012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff70e731e193235ff12c3184510895731a099112ffca4b00246c60003c40f843ce000000006a473044022053760f74c29a879e30a17b5f03a5bb057a5751a39f86fa6ecdedc36a1b7db04c022041d41c9b95f00d2d10a0373322a9025dba66c942196bc9d8adeb0e12d3024728012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff66b7a71b3e50379c8e85fc18fe3f1a408fc985f257036c34702ba205cef09f6f000000006a4730440220499bf9e2db3db6e930228d0661395f65431acae466634d098612fd80b08459ee022040e069fc9e3c60009f521cef54c38aadbd1251aee37940e6018aadb10f194d6a012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff0200e1f5050000000017a9148fc37ad460fdfbd2b44fe446f6e3071a4f64faa6878f447f0b000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac00000000", "54d135fe7cc7ff403aa26e3f8ffbd7f61cf415c9f88403a2a5edd737c5c7031e", "09027acea61b6cc3fb33f5d52f7d088a6b2f75d234e89ca800", "a4885099bba28617ca06cc7f0abec0d8618a50ec5f00fca4602a24e3fc92df10", "Duplicate pushdata 913bcc2be49cb534c20474c4dee1e9c4c317e7eb"],
                vec!["987876", "0000000000000c00901f2049055e2a437c819d79a3d54fd63e6af796cd7b8a79", "000000202694f74969fdb542090e95a56bc8aa2d646e27033850e32f1c5f000000000000f7e53676b3f12d5beb524ed617f2d25f5a93b5f4f52c1ba2678260d72712f8dd0a6dfe5740257e1a4b1768960101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1603e4120ff9c30a1c216900002f424d4920546573742fffffff0001205fa012000000001e76a914c486de584a735ec2f22da7cd9681614681f92173d83d0aa68688ac00000000", "c359ec4e9888b48e15ed69d63fb9564c03d42fab23511d12b22a589149126f31", "010c0b40", "a7170156083f4ad3cf5ee4c7294274cf2eb818f809819e98346a81242d80c802", "Coinbase tx has unparseable output script"],
                vec!["1263442", "000000006f27ddfe1dd680044a34548f41bed47eba9e6f0b310da21423bc5f33", "000000201c8d1a529c39a396db2db234d5ec152fa651a2872966daccbde028b400000000083f14492679151dbfaa1a825ef4c18518e780c1f91044180280a7d33f4a98ff5f45765aaddc001d38333b9a02010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff230352471300fe5f45765afe94690a000963676d696e6572343208000000000000000000ffffffff024423a804000000001976a914f2c25ac3d59f3d674b1d1d0a25c27339aaac0ba688ac0000000000000000266a24aa21a9edcb26cb3052426b9ebb4d19c819ef87c19677bbf3a7c46ef0855bd1b2abe83491012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101d20978463906ba4ff5e7192494b88dd5eb0de85d900ab253af909106faa22cc5010000000004000000014777ff000000000016001446c29eabe8208a33aa1023c741fa79aa92e881ff0347304402207d7ca96134f2bcfdd6b536536fdd39ad17793632016936f777ebb32c22943fda02206014d2fb8a6aa58279797f861042ba604ebd2f8f61e5bddbd9d3be5a245047b201004b632103eeaeba7ce5dc2470221e9517fb498e8d6bd4e73b85b8be655196972eb9ccd5566754b2752103a40b74d43df244799d041f32ce1ad515a6cd99501701540e38750d883ae21d3a68ac00000000", "e3c731dccca0b42146d7655b680b5f15b7c9d297f3f22bf28d9d802e79b09c56", "0385acb4f0fe889ef0", "cc08a689e7113a13386172494443c165573804f255ed07d298129416448d0502", "Includes witness data"]
            ],
            vec![
                //vec!["Tx hash", "Tx"],
                vec!["0a510f49749aaaa2638048132eafea959dd8e47e79332dbcb2a14189870e3145", "0100000001ee565501a12a2bfcf80e6e7829f6bfae878acaff4595fc506dfbc05ecbd5513f010000006b483045022100ace7ab8ea157d33ce61f7952b1c59963fbe4ec71e28b9da4f988178852f8e8690220633e4e5488e5a90b1558b8fa4c55709baad0021f496f120c109b6059482f1f45012102ba06a7e1dc9710523bb19298c126e95086bd86e6a70ea259bdc03a9426eabeecfeffffff026c99dc09000000001976a914ac4c878cb776338d6eebd95d35a5abcd8a6bb37888ac348031010000000017a914feb8a29635c56d9cd913122f90678756bf23887687c4210e00"],
                vec!["df3b6ebcfead10c9c21d11fb68f93e7afe2bb6b15aedb1ebdce41d2634559220", "0100000001922a19af80d2a8e17553422cf4c215ff60125d68d01e40ea0fd2effdd0ea48b9010000006a47304402205a64ef9abcd9aca7d80b40be29ed1311a38decd2a5ae96e5795baee17027e06102204d5d96b8c8928e8f83f4f32de48410b546980a9c6d69b899c95cc848d47f2e8301210316cff587a01a2736d5e12e53551b18d73780b83c3bfb4fcf209c869b11b6415effffffff0220a10700000000001976a9147b87c1509892f1986a0d601b4945bdb20087cf7088ac5e44d81a000000001976a914c01a7ca16b47be50cbdbc60724f701d52d75156688ac00000000"],
                vec!["226351667e09bd4b4b3aa76caf6df5836615d25f365025a51e7a0d63585fa203", "0100000002ba7da264b01a914714d612af3bd84ed8a6576b3e9d01562c863dd8e42666d456010000006a47304402204a33532929d1f96f93eb4533ba48ec2d2078ba635edc85fb22f1f0418b41dcda02203796c3067bb9a1771eb7ee189d4459a87f5e437389c80f48ca6432b58976fec4012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffffba7da264b01a914714d612af3bd84ed8a6576b3e9d01562c863dd8e42666d456000000006b483045022100a2d79b9d09ebce0c0562be11c892e08a10389e4df114f68f71657fa7e6b8e5ef02207147b597d5d53283a9da0a9acc491d20f430d9d09ea3c78f4b26433760e67ab6012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff0200e1f505000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac7faffc00000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac00000000"],
                vec!["f56da6d0bb5807561c29093066edd1d505c2fa4ae89bb895c4318481d360fd3f", "010000000203a25f58630d7a1ea52550365fd2156683f56daf6ca73a4b4bbd097e66516322010000006a47304402204efc3d70e4ca3049c2a425025edf22d5ca355f9ec899dbfbbeeb2268533a0f2b02204780d3739653035af4814ea52e1396d021953f948c29754edd0ee537364603dc012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff03a25f58630d7a1ea52550365fd2156683f56daf6ca73a4b4bbd097e66516322000000006a47304402202d96defdc5b4af71d6ba28c9a6042c2d5ee7bc6de565d4db84ef517445626e03022022da80320e9e489c8f41b74833dfb6a54a4eb5087cdb46eb663eef0b25caa526012103f7a897e4dbecab2264b21917f90664ea8256189ea725d28740cf7ba5d85b5763ffffffff0200e1f5050000000017a914b7e6f7ff8658b2d1fb107e3d7be7af4742e6b1b3876f88fc00000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac00000000"],
                vec!["926ba916aa1487be7e500477e57cccf2ed27ce65baf11e73840fe3cc019437a5", "0100000003ff395e23869a7cadeff1656ac7f150dcd4d8d0e15f4688a85c6b66def5dcbde2000000006a47304402207ffe44e5437a31fad2a92b1b033ec2c5d2aa1666271b5b95b13b33358f4f410302205b7ffed9591a74ba39184ece8293385e742f71f731582ee527757663a7d41d300121033ab1d45ea93afd526276b2a32740678e4fad03c1188a78e502eb0186cf8e1d39ffffffffc2e3fda6a120ed7d6c1b9e71c09721e76a659dfe976aa8b676c6333b38a99352000000006a4730440220639fb86f45c3f7145716ea2160d2dbe189afcca5634a40b3e1e12b99ef31c2f10220291267122c98d243cede5c0002e74489604aa38ebadc6f5d263c62f09e8c71c9012103beaa3fa5614017f3dbc39c9e587b0669c876e4e25454e910b1e2aad2769fff29ffffffffe3a4bcfa73233d52372d901199a3968a186a409a1b09987c6a5bdfee001ff578000000006b4830450221008c70dead71563ebd63b3451df25279406f29206d67a1c2832aeae03d7dad4d8702203b6bd9aa02e38886b60f20d5e6ea3b0d741025e1f2a2a58b2a58de1cc43bdf72012103beaa3fa5614017f3dbc39c9e587b0669c876e4e25454e910b1e2aad2769fff29ffffffff0270160000000000001976a914b19fbc63ce7e40c6fd563873b8fefb71596b804488aca0860100000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88ac00000000"],
                vec!["ce43f8403c00606c24004bcaff1291091a7395085184312cf15f2393e131e770", "010000000155ef5e61d796ef5e772762849c1e2783038e3a51119a3f6893195924b454355b010000006a4730440220522cbbd4a9a89325854b60959780bb7424a5b0e83915ca070b4db3bf73c1566702201fd8f2c2ed4cfbc880daefdb0028532149236cb8cad15d33880b6a084822c0a10121038c617df5ad4bb4386b0a3ef2a078efde3a4aa7c28cea0f40cf930ebfccde2ca7ffffffff0290f4f700000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88acfb4f9226010000001976a9142d1b5d0c4e95afd2f33d9d73c0a614a64c19019688ac00000000"],
                vec!["6f9ff0ce05a22b70346c0357f285c98f401a3ffe18fc858e9c37503e1ba7b766", "01000000011bd7cfb432df16c0579efee7603495e64070193d76ed1376e4229f019ddb4333010000006a473044022058dd39019df64e0e54e13b19edf1539cc1eb064f532326c0ac8e90afac02a79f022015a6355e2e43a201053e017e903fb877018bd675ee694b8f3e48a357a54987d00121037cc791eacc664941b9e70346a2812a410c989e0f36c96d8919c800832d884d23ffffffff0200497f0f000000001976a914913bcc2be49cb534c20474c4dee1e9c4c317e7eb88acd221181a010000001976a914721386b921c73e94d7af7f5db1695f91d180471088ac00000000"],
                vec!["c52ca2fa069190af53b20a905de80debd58db8942419e7f54fba0639467809d2", "02000000000101ed30ca30ee83f13579da294e15c9d339b35d33c5e76d2fda68990107d30ff00700000000006db7b08002360b0000000000001600148154619cb0e7513fcdb1eb90cc9f86f3793b9d8ec382ff000000000022002027a5000c7917f785d8fc6e5a55adfca8717ecb973ebb7743849ff956d896a7ed04004730440220503890e657773607fb05c9ef4c4e73b0ab847497ee67b3b8cefb3688a73333180220066db0ca943a5932f309ac9d4f191300711a5fc206d7c3babd85f025eac30bca01473044022055f05c3072dfd389104af1f5ccd56fb5433efc602694f1f384aab703c77ac78002203c1133981d66dc48183e72a19cc0974b93002d35ad7d6ee4278d46b4e96f871a0147522102989711912d88acf5a4a18081104f99c2f8680a7de23f829f28db31fdb45b7a7a2102f0406fa1b49a9bb10c191fd83e2359867ecdace5ea990ce63d11478ed5877f1852ae81534220"]
            ]
        ];
        let ref blocks = data[0];
        let ref txs = data[1];
        for t in 0..7 {
            let mut txmap = HashMap::new();
            let ref test_case = blocks[t];
            let block_hash = sha256d::Hash::from_hex(test_case[1]).unwrap();
            let previous_header_hash = sha256d::Hash::from_hex(test_case[3]).unwrap();
            let header_hash = sha256d::Hash::from_hex(test_case[5]).unwrap();
            let block: Block = decode(hex::decode(test_case[2]).unwrap()).unwrap();
            assert_eq!(block.bitcoin_hash(), block_hash);

            for tx in &block.txdata {
                for (ix, out) in tx.output.iter().enumerate() {
                    txmap.insert(OutPoint { txid: tx.txid(), vout: ix as u32 }, out.script_pubkey.clone());
                }
            }
            for i in 0..8 {
                let ref line = txs[i];
                let tx: blockdata::transaction::Transaction = decode(hex::decode(line[1]).unwrap()).unwrap();
                assert_eq!(tx.txid().to_string().as_str(), line[0]);
                for (ix, out) in tx.output.iter().enumerate() {
                    txmap.insert(OutPoint { txid: tx.txid(), vout: ix as u32 }, out.script_pubkey.clone());
                }
            }

            let test_filter = hex::decode(test_case[4]).unwrap();
            let mut constructed_filter = Cursor::new(Vec::new());
            {
                let mut writer = BlockFilterWriter::new(&mut constructed_filter, &block);
                writer.add_output_scripts();
                writer.add_input_scripts(
                    |o| if let Some(s) = txmap.get(o) {
                        Ok(s.clone())
                    } else {
                        Err(Error::UtxoMissing(o.clone()))
                    }).unwrap();
                writer.finish().unwrap();
            }

            let filter = constructed_filter.into_inner();
            assert_eq!(test_filter, filter);
            let filter_hash = sha256d::Hash::hash(filter.as_slice());
            let mut header_data = [0u8; 64];
            header_data[0..32].copy_from_slice(&filter_hash[..]);
            header_data[32..64].copy_from_slice(&previous_header_hash[..]);
            let filter_header_hash = sha256d::Hash::hash(&header_data);
            assert_eq!(filter_header_hash, header_hash);
        }
    }

    #[test]
    fn test_filter () {
        let mut patterns = HashSet::new();

        patterns.insert(hex::decode("000000").unwrap());
        patterns.insert(hex::decode("111111").unwrap());
        patterns.insert(hex::decode("222222").unwrap());
        patterns.insert(hex::decode("333333").unwrap());
        patterns.insert(hex::decode("444444").unwrap());
        patterns.insert(hex::decode("555555").unwrap());
        patterns.insert(hex::decode("666666").unwrap());
        patterns.insert(hex::decode("777777").unwrap());
        patterns.insert(hex::decode("888888").unwrap());
        patterns.insert(hex::decode("999999").unwrap());
        patterns.insert(hex::decode("aaaaaa").unwrap());
        patterns.insert(hex::decode("bbbbbb").unwrap());
        patterns.insert(hex::decode("cccccc").unwrap());
        patterns.insert(hex::decode("dddddd").unwrap());
        patterns.insert(hex::decode("eeeeee").unwrap());
        patterns.insert(hex::decode("ffffff").unwrap());

        let mut out = Cursor::new(Vec::new());
        {
            let mut writer = GCSFilterWriter::new(&mut out, 0, 0);
            for p in &patterns {
                writer.add_element(p.as_slice());
            }
            writer.finish().unwrap();
        }

        let bytes = out.into_inner();

        {
            let mut query = Vec::new();
            query.push(hex::decode("abcdef").unwrap());
            query.push(hex::decode("eeeeee").unwrap());

            let reader = GCSFilterReader::new(0, 0);
            let mut input = Cursor::new(bytes.clone());
            assert!(reader.match_any(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let mut query = Vec::new();
            query.push(hex::decode("abcdef").unwrap());
            query.push(hex::decode("123456").unwrap());

            let reader = GCSFilterReader::new(0, 0);
            let mut input = Cursor::new(bytes.clone());
            assert!(!reader.match_any(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let reader = GCSFilterReader::new(0, 0);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            let mut input = Cursor::new(bytes.clone());
            assert!(reader.match_all(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
        {
            let reader = GCSFilterReader::new(0, 0);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p.clone());
            }
            query.push(hex::decode("abcdef").unwrap());
            let mut input = Cursor::new(bytes.clone());
            assert!(!reader.match_all(&mut input, &mut query.iter().map(|v| v.as_slice())).unwrap());
        }
    }

    #[test]
    fn test_bit_stream() {
        let mut out = Cursor::new(Vec::new());
        {
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
        let bytes = out.into_inner();
        assert_eq!("01011010110000110000000001110000", format!("{:08b}{:08b}{:08b}{:08b}", bytes[0], bytes[1], bytes[2], bytes[3]));
        {
            let mut input = Cursor::new(bytes);
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
