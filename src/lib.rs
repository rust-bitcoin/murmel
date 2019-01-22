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
//! # Bitcoin SPV client
//!
//! This library implements a Simplified Payment Verification (SPV) client for Bitcoin
//!

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]
#![deny(unused_must_use)]

extern crate mio;
extern crate bitcoin;
extern crate lightning;
extern crate hammersbald;
extern crate byteorder;
#[macro_use]
extern crate log;
extern crate rand;
extern crate rusqlite;
extern crate siphasher;
extern crate futures;
extern crate futures_timer;

mod headercache;
mod filtercache;
mod chaindb;
mod filtercalculator;
mod configdb;
mod dispatcher;
mod error;
mod connector;
mod blockfilter;
mod p2p;
mod dns;
pub mod constructor;