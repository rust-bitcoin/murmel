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
//! # Construct the Murmel stack
//!
//! Assembles modules of this library to a complete service
//!

use bitcoin::{
    network::{
        constants::Network
    }
};
use blockserver::BlockServer;
use chaindb::{ChainDB, SharedChainDB};
use dispatcher::Dispatcher;
use dns::dns_seed;
use error::MurmelError;
use filtercalculator::FilterCalculator;
use filtered::Filtered;
use filterserver::FilterServer;
use futures::{
    executor::ThreadPool,
    future,
    prelude::*,
};
use headerdownload::HeaderDownload;
use p2p::{P2P, P2PControl, PeerMessageSender, PeerSource, SERVICE_BLOCKS, SERVICE_FILTERS};
use ping::Ping;
use rand::{RngCore, thread_rng};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    sync::{Arc, mpsc, Mutex, RwLock, atomic::AtomicUsize},
};
use timeout::Timeout;
use downstream::DownStreamDummy;
use downstream::SharedDownstream;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message::RawNetworkMessage;
use p2p::BitcoinP2PConfig;

const MAX_PROTOCOL_VERSION: u32 = 70001;

/// The complete stack
pub struct Constructor {
    p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
    /// this should be accessed by Lightning
    pub downstream: SharedDownstream,
    /// message dispatcher
    dispatcher: Dispatcher<NetworkMessage>,
    server: bool,
}

impl Constructor {
    /// open DBs
    pub fn open_db(path: Option<&Path>, network: Network, server: bool, script_cache_size: usize, birth: u64) -> Result<SharedChainDB, MurmelError> {
        let mut chaindb =
        if let Some(path) = path {
            ChainDB::new(path, network, script_cache_size)?
        } else {
            ChainDB::mem(network, script_cache_size)?
        };
        chaindb.init(server)?;
        Ok(Arc::new(RwLock::new(chaindb)))
    }

    /// Construct the stack
    pub fn new(user_agent: String, network: Network, listen: Vec<SocketAddr>, server: bool, chaindb: SharedChainDB) -> Result<Constructor, MurmelError> {
        let back_pressure = if server {
            1000
        } else {
            10
        };

        let (to_dispatcher, from_p2p) = mpsc::sync_channel(back_pressure);


        let p2pconfig = BitcoinP2PConfig {
            network,
            nonce: thread_rng().next_u64(),
            max_protocol_version: MAX_PROTOCOL_VERSION,
            user_agent: "murmel: 0.1.0".to_owned(),
            height: AtomicUsize::new(0),
            server: !listen.is_empty()
        };

        let (p2p, p2p_control) =
            P2P::new(p2pconfig, PeerMessageSender::new(to_dispatcher), back_pressure);

        #[cfg(feature="lightning")] let lightning = Arc::new(Mutex::new(LightningConnector::new(network, p2p_control.clone())));
        #[cfg(not(feature="lightning"))] let lightning = Arc::new(Mutex::new(DownStreamDummy{}));


        let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

        let mut dispatcher = Dispatcher::new(from_p2p);

        dispatcher.add_listener(HeaderDownload::new(chaindb.clone(), p2p_control.clone(), timeout.clone(), lightning.clone()));
        dispatcher.add_listener(Ping::new(p2p_control.clone(), timeout.clone()));
        if server {
            dispatcher.add_listener(FilterCalculator::new(network, chaindb.clone(), p2p_control.clone(), timeout.clone()));
            dispatcher.add_listener(FilterServer::new(chaindb.clone(), p2p_control.clone()));
            dispatcher.add_listener(BlockServer::new(chaindb.clone(), p2p_control.clone()));
        } else {
            dispatcher.add_listener(Filtered::new(chaindb.clone(), p2p_control.clone(), timeout.clone(), lightning.clone(), None));
        }


        for addr in &listen {
            p2p_control.send(P2PControl::Bind(addr.clone()));
        }

        Ok(Constructor { p2p, dispatcher, server, downstream: lightning })
    }

    /// Run the stack. This should be called AFTER registering listener of the ChainWatchInterface,
    /// so they are called as the stack catches up with the blockchain
    /// * peers - connect to these peers at startup (might be empty)
    /// * min_connections - keep connections with at least this number of peers. Peers will be randomly chosen
    /// from those discovered in earlier runs
    pub fn run(&mut self, network: Network, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Result<(), MurmelError> {
        let needed_services = if self.server {
            0
        } else {
            SERVICE_BLOCKS + SERVICE_FILTERS
        };

        let p2p2 = self.p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run(needed_services, ctx).unwrap();
            Ok(Async::Ready(()))
        }));

        let mut thread_pool = ThreadPool::new()?;

        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        // the task that keeps us connected
        // note that this call does not return
        thread_pool.run(self.keep_connected(network,self.p2p.clone(), peers, min_connections, nodns)).unwrap();
        Ok(())
    }

    fn keep_connected(&self, network: Network, p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Box<Future<Item=(), Error=Never> + Send> {

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer(PeerSource::Outgoing(addr.clone())));
        }

        struct KeepConnected {
            network: Network,
            min_connections: usize,
            connections: Vec<Box<Future<Item=SocketAddr, Error=MurmelError> + Send>>,
            p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
            dns: Vec<SocketAddr>,
            earlier: HashSet<SocketAddr>,
            nodns: bool,
        }

        // this task runs until it runs out of peers
        impl Future for KeepConnected {
            type Item = ();
            type Error = Never;

            fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
                // return from this loop with 'pending' if enough peers are connected
                loop {
                    // add further peers from db if needed
                    self.peers_from_db();
                    if !self.nodns {
                        self.dns_lookup();
                    }

                    if self.connections.len() == 0 {
                        // run out of peers. this is fatal
                        error!("no more peers to connect");
                        return Ok(Async::Ready(()));
                    }
                    // find a finished peer
                    let finished = self.connections.iter_mut().enumerate().filter_map(|(i, f)| {
                        // if any of them finished
                        // note that poll is reusing context of this poll, so wakeups come here
                        match f.poll(cx) {
                            Ok(Async::Pending) => None,
                            Ok(Async::Ready(e)) => {
                                trace!("woke up to lost peer");
                                Some((i, Ok(e)))
                            }
                            Err(e) => {
                                trace!("woke up to peer error");
                                Some((i, Err(e)))
                            }
                        }
                    }).next();
                    match finished {
                        Some((i, _)) => self.connections.remove(i),
                        None => return Ok(Async::Pending)
                    };
                }
            }
        }

        impl KeepConnected {
            fn peers_from_db(&mut self) {
                // TODO
            }

            fn dns_lookup(&mut self) {
                while self.connections.len() < self.min_connections {
                    if self.dns.len() == 0 {
                        self.dns = dns_seed(self.network);
                    }
                    if self.dns.len() > 0 {
                        let mut rng = thread_rng();
                        let addr = self.dns[(rng.next_u64() as usize) % self.dns.len()];
                        self.connections.push(self.p2p.add_peer(PeerSource::Outgoing(addr)));
                    }
                    else {
                        break;
                    }
                }
            }
        }

        Box::new(KeepConnected { network, min_connections, connections: added, p2p, dns: Vec::new(), nodns, earlier: HashSet::new() })
    }
}
