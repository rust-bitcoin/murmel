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
extern crate bitcoin;
extern crate log;
extern crate murmel;
extern crate rand;
extern crate simple_logger;

use bitcoin::network::constants::Network;
use log::Level;
use murmel::{
    constructor::Constructor
};

use std::{
    env::args,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    str::FromStr,
    time::SystemTime
};

pub fn main() {
    if find_opt("help") {
        println!("Murmel Client");
        println!("{} [--help] [--log trace|debug|info|warn|error] [--connections n] [--peer ip_address:port] [--db database_file] [--network main|test]", args().next().unwrap());
        println!("--log level: level is one of trace|debug|info|warn|error");
        println!("--connections n: maintain at least n connections");
        println!("--peer ip_address: connect to the given peer at start. You may use more than one --peer option.");
        println!("--db file: store data in the given sqlite database file. Created if does not exist.");
        println!("--network net: net is one of main|test|regtest for corresponding Bitcoin networks");
        println!("--nodns : do not use dns seed");
        println!("--birth unixtime : blocks will be downloaded if matching filters after this time stamp");
        println!("defaults:");
        println!("--peer 127.0.0.1:8333");
        println!("--db client.db");
        println!("--log debug");
        println!("--nodns");
        println!("--network main");
        return;
    }
    if let Some (log) = find_arg("log") {
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
        simple_logger::init_with_level(Level::Debug).unwrap();
    }

    let mut network = Network::Bitcoin;
    if let Some(net) = find_arg("network") {
        match net.as_str() {
            "main" => network = Network::Bitcoin,
            "test" => network = Network::Testnet,
            "regtest" => network = Network::Regtest,
            _ => network = Network::Bitcoin
        }
    }

    let mut peers = get_peers();
    if peers.is_empty () {
        let port = match network {
            Network::Bitcoin => 8333,
            Network::Testnet => 18333,
            Network::Regtest => 18444,
        };
        peers.push(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)));
    }
    let mut connections = 1;
    if let Some(numstring) = find_arg("connections") {
        connections = numstring.parse().unwrap();
    }
    let listen = get_listeners();
    let birth = if let Some(timestamp) = find_arg("birth") {
        timestamp.parse::<u64>().unwrap()
    }
    else {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    };

    let chaindb =
        if let Some(path) = find_arg("db") {
            Constructor::open_db(Some(&Path::new(path.as_str())), network,  birth).unwrap()
        } else {
            Constructor::open_db(Some(&Path::new("client.db")), network, birth).unwrap()
        };
    let mut spv = Constructor::new(network, listen, chaindb).unwrap();
    spv.run(network, peers, connections).expect("can not start node");
}

fn get_peers() -> Vec<SocketAddr> {
    find_args("peer").iter().map(|s| SocketAddr::from_str(s).unwrap()).collect()
}

fn get_listeners() -> Vec<SocketAddr> {
    find_args("listen").iter().map(|s| SocketAddr::from_str(s).unwrap()).collect()
}

// Returns key-value zipped iterator.
fn zipped_args() -> impl Iterator<Item = (String, String)> {
    let key_args = args().filter(|arg| arg.starts_with("--")).map(|mut arg| arg.split_off(2));
    let val_args = args().skip(1).filter(|arg| !arg.starts_with("--"));
    key_args.zip(val_args)
}

fn find_opt(key: &str) -> bool {
    let mut key_args = args().filter(|arg| arg.starts_with("--")).map(|mut arg| arg.split_off(2));
    key_args.find(|ref k| k.as_str() == key).is_some()
}

fn find_arg(key: &str) -> Option<String> {
    zipped_args().find(|&(ref k, _)| k.as_str() == key).map(|(_, v)| v)
}

fn find_args(key: &str) -> Vec<String> {
    zipped_args().filter(|&(ref k, _)| k.as_str() == key).map(|(_, v)| v).collect()
}
