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
//! # Murmel Bitcoin node
//!
//! This library implements a Simplified Payment Verification (SPV) of Bitcoin
//!

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

extern crate bitcoin;
extern crate lightning;
extern crate byteorder;
extern crate futures;
extern crate futures_timer;
extern crate hammersbald;
#[macro_use]
extern crate log;
extern crate lru_cache;
extern crate mio;
extern crate rand;
extern crate rayon;
extern crate rusqlite;
extern crate siphasher;

mod connector;
mod filtered;
mod ping;
mod timeout;
mod blockserver;
mod scriptcache;
mod filterserver;
mod headerdownload;
mod headercache;
mod filtercache;
mod chaindb;
mod filtercalculator;
mod configdb;
mod dispatcher;
mod error;
mod blockfilter;
mod p2p;
mod dns;
pub mod constructor;