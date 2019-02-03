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
//! # Murmel Error
//!
//! All modules of this library use this error class to indicate problems.
//!

use bitcoin::consensus::encode;
use bitcoin::util;
use hammersbald::HammersbaldError;
use rusqlite;
use std::convert;
use std::error::Error;
use std::fmt;
use std::io;

/// An error class to offer a unified error interface upstream
pub enum MurmelError {
    /// bad proof of work
    SpvBadProofOfWork,
    /// unconnected header chain detected
    UnconnectedHeader,
    /// no chain tip found
    NoTip,
    /// no peers to connect to
    NoPeers,
    /// unknown UTXO referred
    UnknownUTXO,
    /// Merkle root of block does not match the header
    BadMerkleRoot,
    /// downstream error
    Downstream(String),
    /// Network IO error
    IO(io::Error),
    /// Database error
    DB(rusqlite::Error),
    /// Bitcoin util error
    Util(util::Error),
    /// Bitcoin serialize error
    Serialize(encode::Error),
    /// Hammersbald error
    Hammersbald(HammersbaldError)
}

impl Error for MurmelError {
    fn description(&self) -> &str {
        match *self {
            MurmelError::SpvBadProofOfWork => "bad proof of work",
            MurmelError::UnconnectedHeader => "unconnected header",
            MurmelError::NoTip => "no chain tip found",
            MurmelError::UnknownUTXO => "unknown utxo",
            MurmelError::NoPeers => "no peers",
            MurmelError::BadMerkleRoot => "merkle root of header does not match transaction list",
            MurmelError::Downstream(ref s) => s,
            MurmelError::IO(ref err) => err.description(),
            MurmelError::DB(ref err) => err.description(),
            MurmelError::Util(ref err) => err.description(),
            MurmelError::Hammersbald(ref err) => err.description(),
            MurmelError::Serialize(ref err) => err.description()
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            MurmelError::SpvBadProofOfWork => None,
            MurmelError::UnconnectedHeader => None,
            MurmelError::NoTip => None,
            MurmelError::NoPeers => None,
            MurmelError::UnknownUTXO => None,
            MurmelError::Downstream(_) => None,
            MurmelError::BadMerkleRoot => None,
            MurmelError::IO(ref err) => Some(err),
            MurmelError::DB(ref err) => Some(err),
            MurmelError::Util(ref err) => Some(err),
            MurmelError::Hammersbald(ref err) => Some(err),
            MurmelError::Serialize(ref err) => Some(err)
        }
    }
}

impl fmt::Display for MurmelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            MurmelError::SpvBadProofOfWork |
            MurmelError::UnconnectedHeader |
            MurmelError::NoTip |
            MurmelError::NoPeers | MurmelError::BadMerkleRoot |
            MurmelError::UnknownUTXO => write!(f, "{}", self.description()),
            MurmelError::Downstream(ref s) => write!(f, "{}", s),
            MurmelError::IO(ref err) => write!(f, "IO error: {}", err),
            MurmelError::DB(ref err) => write!(f, "DB error: {}", err),
            MurmelError::Util(ref err) => write!(f, "Util error: {}", err),
            MurmelError::Hammersbald(ref err) => write!(f, "Hammersbald error: {}", err),
            MurmelError::Serialize(ref err) => write!(f, "Serialize error: {}", err),
        }
    }
}

impl fmt::Debug for MurmelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self as &fmt::Display).fmt(f)
    }
}

impl convert::From<MurmelError> for io::Error {
    fn from(err: MurmelError) -> io::Error {
        match err {
            MurmelError::IO(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, err.description())
        }
    }
}

impl convert::From<io::Error> for MurmelError {
    fn from(err: io::Error) -> MurmelError {
        MurmelError::IO(err)
    }
}


impl convert::From<util::Error> for MurmelError {
    fn from(err: util::Error) -> MurmelError {
        MurmelError::Util(err)
    }
}

impl convert::From<rusqlite::Error> for MurmelError {
    fn from(err: rusqlite::Error) -> MurmelError {
        MurmelError::DB(err)
    }
}

impl convert::From<HammersbaldError> for MurmelError {
    fn from(err: HammersbaldError) -> MurmelError {
        MurmelError::Hammersbald(err)
    }
}

impl convert::From<encode::Error> for MurmelError {
    fn from(err: encode::Error) -> MurmelError {
        MurmelError::Serialize(err)
    }
}

impl convert::From<Box<Error>> for MurmelError {
    fn from(err: Box<Error>) -> Self {
        MurmelError::Downstream(err.description().to_owned())
    }
}