//Copyright 2018 Tamas Blummer
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
use rusqlite;
use std::convert;
use std::io;
use std::net::SocketAddr;
use failure::Fail;

/// An error class to offer a unified error interface upstream
#[derive(Debug, Fail)]
pub enum SPVError {
    #[fail(display = "Generic: {}", _0)]
    Generic(String),
    #[fail(display = "Misbehaving: {} peer={}", _1, _2)]
    Misbehaving(u16, String, SocketAddr),
    #[fail(display = "IO error: {}", _0)]
    IO(#[cause] io::Error),
    #[fail(display = "DB error: {}", _0)]
    DB(#[cause] rusqlite::Error),
    #[fail(display = "Panic: {}", _0)]
    Panic(String),
}

impl convert::From<SPVError> for io::Error {
    fn from(err: SPVError) -> io::Error {
        match err {
            SPVError::IO(e) => e,
            _ => io::Error::new(io::ErrorKind::Other, err.compat())
        }
    }
}

impl convert::From<io::Error> for SPVError {
    fn from(err: io::Error) -> SPVError {
        SPVError::IO(err)
    }
}

impl convert::From<rusqlite::Error> for SPVError {
    fn from(err: rusqlite::Error) -> SPVError {
        SPVError::DB(err)
    }
}
