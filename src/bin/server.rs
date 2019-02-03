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
use murmel::constructor::Constructor;
use std::env::args;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::str::FromStr;

pub fn main() {
    if find_opt("help") {
        println!("Murmel Server");
        println!("{} [--help] [--log trace|debug|info|warn|error] [--connections n] [--peer ip_address:port] [--db database_file] [--network main|test]", args().next().unwrap());
        println!("warning: due to a bug in args parsing options without args must be after options with args");
        println!("--log level: level is one of trace|debug|info|warn|error");
        println!("--connections n: maintain at least n connections");
        println!("--peer ip_address: connect to the given peer at start. You may use more than one --peer option.");
        println!("--db file: store data in the given sqlite database file. Created if does not exist.");
        println!("--network net: net is one of main|test for corresponding Bitcoin networks");
        println!("--listen ip_address:port : accept incoming connection requests");
        println!("--nodns : do not use dns seed");
        println!("--utxo-cache : cache of utxo in millions - set it up to 60 if doing initial load and you have plenty of RAM");
        println!("defaults:");
        println!("--db server.db");
        println!("--log debug");
        println!("--listen 127.0.0.1:8333");
        println!("--connections 1");
        println!("--network main");
        println!("in memory database");
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
            _ => network = Network::Bitcoin
        }
    }

    let mut cache = 0;
    if let Some(numstring) = find_arg("utxo-cache") {
        cache = 1024usize *1024usize * numstring.parse::<usize>().unwrap() as usize;
    }

    let peers = get_peers();
    let mut connections = 1;
    if let Some(numstring) = find_arg("connections") {
        connections = numstring.parse().unwrap();
    }
    let mut spv;
    let mut listen = get_listeners();
    if listen.is_empty() {
        listen.push(SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8333)));
    }
    if let Some(path) = find_arg("db") {
        spv = Constructor::new("/Murmel:0.1.0/".to_string(), network, Path::new(path.as_str()),  listen, true, cache, 0).unwrap();
    }
    else {
        spv = Constructor::new("/Murmel:0.1.0/".to_string(), network, Path::new("server.db"), listen, true, cache, 0).unwrap();
    }
    spv.run(peers, connections, find_opt("nodns")).expect("can not start node");
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
