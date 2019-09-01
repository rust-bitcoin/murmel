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
use chaindb::{ChainDB, SharedChainDB};
use dispatcher::Dispatcher;
use dns::dns_seed;
use error::Error;
use futures::{
    executor::ThreadPool,
    future,
    prelude::*,
};
use headerdownload::HeaderDownload;
use p2p::{P2P, P2PControl, PeerMessageSender, PeerSource};
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
use futures::task::Waker;

const MAX_PROTOCOL_VERSION: u32 = 70001;

/// The complete stack
pub struct Constructor {
    p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
    /// this should be accessed by Lightning
    pub downstream: SharedDownstream
}

impl Constructor {
    /// open DBs
    pub fn open_db(path: Option<&Path>, network: Network, _birth: u64) -> Result<SharedChainDB, Error> {
        let mut chaindb =
            if let Some(path) = path {
                ChainDB::new(path, network)?
            } else {
                ChainDB::mem(network)?
            };
        chaindb.init()?;
        Ok(Arc::new(RwLock::new(chaindb)))
    }

    /// Construct the stack
    pub fn new(network: Network, listen: Vec<SocketAddr>, chaindb: SharedChainDB) -> Result<Constructor, Error> {
        const BACK_PRESSURE:usize = 10;

        let (to_dispatcher, from_p2p) = mpsc::sync_channel(BACK_PRESSURE);


        let p2pconfig = BitcoinP2PConfig {
            network,
            nonce: thread_rng().next_u64(),
            max_protocol_version: MAX_PROTOCOL_VERSION,
            user_agent: "murmel: 0.1.0".to_owned(),
            height: AtomicUsize::new(0),
            server: !listen.is_empty()
        };

        let (p2p, p2p_control) =
            P2P::new(p2pconfig, PeerMessageSender::new(to_dispatcher), BACK_PRESSURE);

        #[cfg(feature = "lightning")] let lightning = Arc::new(Mutex::new(LightningConnector::new(network, p2p_control.clone())));
        #[cfg(not(feature = "lightning"))] let lightning = Arc::new(Mutex::new(DownStreamDummy {}));


        let timeout = Arc::new(Mutex::new(Timeout::new(p2p_control.clone())));

        let mut dispatcher = Dispatcher::new(from_p2p);

        dispatcher.add_listener(HeaderDownload::new(chaindb.clone(), p2p_control.clone(), timeout.clone(), lightning.clone()));
        dispatcher.add_listener(Ping::new(p2p_control.clone(), timeout.clone()));

        for addr in &listen {
            p2p_control.send(P2PControl::Bind(addr.clone()));
        }

        Ok(Constructor { p2p, downstream: lightning })
    }

    /// Run the stack. This should be called AFTER registering listener of the ChainWatchInterface,
    /// so they are called as the stack catches up with the blockchain
    /// * peers - connect to these peers at startup (might be empty)
    /// * min_connections - keep connections with at least this number of peers. Peers will be randomly chosen
    /// from those discovered in earlier runs
    pub fn run(&mut self, network: Network, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Result<(), Error> {
        let needed_services = 0;

        let p2p2 = self.p2p.clone();
        let p2p_task = Box::new(future::poll_fn(move |ctx| {
            p2p2.run("bitcoin", needed_services, ctx).unwrap();
            Ok(Async::Ready(()))
        }));

        let mut thread_pool = ThreadPool::new()?;

        // start the task that runs all network communication
        thread_pool.spawn(p2p_task).unwrap();

        // the task that keeps us connected
        // note that this call does not return
        thread_pool.run(Self::keep_connected(network, self.p2p.clone(), peers, min_connections, nodns)).unwrap();
        Ok(())
    }

    fn keep_connected(network: Network, p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> KeepConnected {
        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer("bitcoin", PeerSource::Outgoing(addr.clone())));
        }

        return KeepConnected {
            network,
            min_connections,
            connections: added,
            p2p,
            dns: Vec::new(),
            earlier: HashSet::new(),
            nodns,
            waker: Arc::new(Mutex::new(None))
        };
    }
}
struct KeepConnected {
    network: Network,
    min_connections: usize,
    connections: Vec<Box<dyn Future<Item=SocketAddr, Error=Error> + Send>>,
    p2p: Arc<P2P<NetworkMessage, RawNetworkMessage, BitcoinP2PConfig>>,
    dns: Vec<SocketAddr>,
    earlier: HashSet<SocketAddr>,
    nodns: bool,
    waker: Arc<Mutex<Option<Waker>>>
}

// this task runs until it runs out of peers
impl Future for KeepConnected {
    type Item = ();
    type Error = Never;

    fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
        // find a finished peers
        let finished = self.connections.iter_mut().enumerate().filter_map(|(i, c)| {
            match c.poll(cx) {
                Ok(Async::Pending) => None,
                Ok(Async::Ready(address)) => {
                    debug!("keep connected woke up to lost peer at {}", address);
                    Some(i)
                },
                Err(e) => {
                    debug!("keep connected woke up to error {:?}", e);
                    Some(i)
                }
            }
        }).collect::<Vec<_>>();
        let mut n = 0;
        for i in finished.iter() {
            self.connections.remove(*i - n);
            n += 1;
        }
        while self.connections.len() < self.min_connections {
            if let Some(addr) = self.get_an_address() {
                self.connections.push(self.p2p.add_peer("bitcoin", PeerSource::Outgoing(addr)));
            }
            else {
                warn!("no more bitcoin peers to connect, currently have {}", self.connections.len());
                break;
            }
        }
        let mut waker = self.waker.lock().unwrap();
        *waker = Some(cx.waker().clone());
        return Ok(Async::Pending);
    }
}

impl KeepConnected {
    fn get_an_address(&mut self) -> Option<SocketAddr> {
        if !self.nodns && self.dns.len() == 0 {
            self.dns = dns_seed(self.network);
        }
        if self.dns.len() > 0 {
            let eligible = self.dns.iter().filter(|a| !self.earlier.contains(a)).cloned().collect::<Vec<_>>();
            if eligible.len() > 0 {
                let mut rng = thread_rng();
                let choice = eligible[(rng.next_u32() as usize) % eligible.len()];
                self.earlier.insert(choice.clone());
                return Some(choice);
            }
        }
        None
    }
}