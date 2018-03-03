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
extern crate bitcoin;
extern crate bitcoin_spv;
extern crate bytes;
extern crate futures;
extern crate log;
extern crate rand;
extern crate simple_logger;
extern crate tokio;
extern crate tokio_core;
extern crate tokio_io;

use bitcoin::network::constants::Network;
use bitcoin_spv::database::DB;
use bitcoin_spv::dispatcher::Dispatcher;
use bitcoin_spv::node::Node;
use log::Level;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use tokio_core::reactor::Core;

/// simple test drive that connects to a local bitcoind
pub fn main() {
    simple_logger::init_with_level(Level::Info).unwrap();
    let mut db = DB::new(Path::new("/tmp/blocks.sqlite")).unwrap();
    create_tables(&mut db);
    let node = Rc::new(Node::new(Network::Bitcoin, db));
    node.load_headers().unwrap();

    let dispatcher = Dispatcher::new(node);

    let mut servers = Vec::new();
    servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333));

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    core.run(dispatcher.run(handle, &servers)).unwrap();
}

fn create_tables(db: &mut DB)
{
    let tx = db.transaction().unwrap();
    tx.create_tables().unwrap();
    tx.commit().unwrap();
}

