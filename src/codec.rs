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
//! # Bitcoin Message codec
//!
//! Encode and decode Bitcoin messages from raw network input
//!


use bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use bitcoin::network::message::RawNetworkMessage;
use bitcoin::network::serialize::{RawDecoder, RawEncoder};
use bitcoin::util;
use bytes::{BufMut, BytesMut};
use std::cmp::{max, min};
use std::io;
use tokio_io::codec::{Decoder, Encoder};

/// A codec for Bitcoin Messages
pub struct BitcoinCodec;

/// A helper class that wrap BytesMut so it implements io::Read and io::Write
struct BufferRW<'a> (&'a mut BytesMut);

impl<'a> io::Write for BufferRW<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if self.0.remaining_mut() < buf.len() {
            self.0.reserve(max(1024, buf.len()));
        }
        self.0.put_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl<'a> io::Read for BufferRW<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let minlen = min(self.0.len(), buf.len());
        buf[..minlen].copy_from_slice(&self.0.split_to(minlen));
        Ok(minlen)
    }
}

impl Encoder for BitcoinCodec {
    type Item = RawNetworkMessage;
    type Error = io::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item.consensus_encode(&mut RawEncoder::new(BufferRW(dst))) {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::WriteZero, e))
        }
    }
}

impl Decoder for BitcoinCodec {
    type Item = RawNetworkMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // TODO: this is a wasteful solution
        // all I'd need is reset src position if decode fails with ByteOrder
        // could however not find a BytesMut API to do so
        let mut buf = src.clone();
        let decode: Result<RawNetworkMessage, util::Error> =
            ConsensusDecodable::consensus_decode(&mut RawDecoder::new(BufferRW(&mut buf)));
        match decode {
            Ok(m) => {
                let sl = src.len();
                src.advance(sl - buf.len());
                Ok(Some(m))
            }
            Err(util::Error::ByteOrder(_)) => Ok(None),
            Err(e) => {
                trace!("invalid data in codec: {} size {}", e, src.len());
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}