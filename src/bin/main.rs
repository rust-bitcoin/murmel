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
extern crate bitcoin;
extern crate bitcoin_spv;
extern crate log;
extern crate rand;
extern crate simple_logger;

mod args;

use bitcoin::network::constants::Network;
use bitcoin_spv::spv::SPV;
use log::Level;
use std::net::SocketAddr;
use std::path::Path;

/// simple test drive that connects to a local bitcoind
pub fn main() {
    if let Some (log) = args::find_arg("log") {
        match log.as_str() {
            "error" => simple_logger::init_with_level(Level::Error).unwrap(),
            "warn" => simple_logger::init_with_level(Level::Warn).unwrap(),
            "info" => simple_logger::init_with_level(Level::Info).unwrap(),
            "debug" => simple_logger::init_with_level(Level::Debug).unwrap(),
            "trace" => simple_logger::init_with_level(Level::Trace).unwrap(),
            _ => simple_logger::init_with_level(Level::Info).unwrap()
        }
    }
    else {
        simple_logger::init_with_level(Level::Info).unwrap();
    }
    let peers = get_peers();
    let mut connections = 1;
    if let Some(numstring) = args::find_arg("connections") {
        connections = numstring.parse().unwrap();
    }
    if let Some(path) = args::find_arg("db") {
        let spv = SPV::new("/rust-spv:0.1.0/".to_string(), Network::Bitcoin, Path::new(path.as_str())).unwrap();
        spv.start(peers, connections);
    }
    else {
        let spv = SPV::new_in_memory("/rust-spv:0.1.0/".to_string(), Network::Bitcoin).unwrap();
        spv.start(peers, connections);
    }
}

use std::str::FromStr;

fn get_peers() -> Vec<SocketAddr> {
    args::find_args("peer").iter().map(|s| SocketAddr::from_str(s).unwrap()).collect()
}
