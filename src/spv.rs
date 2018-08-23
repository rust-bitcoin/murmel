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
//! # SPV
//!
//! Assembles modules of this library to a complete SPV service
//!

use bitcoin::network::constants::Network;
use database::DB;
use error::SPVError;
use lightning::chain::chaininterface::ChainWatchInterface;
use node::Node;
use p2p::P2P;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use p2p::{PeerMap, PeerSource};
use futures::future;
use futures::prelude::*;
use futures::executor::ThreadPool;
use dns::dns_seed;
use rand::{thread_rng, Rng};
use std::collections::HashSet;

const MAX_PROTOCOL_VERSION :u32 = 70001;

/// The complete SPV stack
pub struct SPV{
	node: Arc<Node>,
	p2p: Arc<P2P>,
    thread_pool: ThreadPool,
    db: Arc<Mutex<DB>>
}

impl SPV {
    /// Initialize the SPV stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    ///      db - file path to store the headers and blocks database
    /// The method will read previously stored headers from the database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new(user_agent :String, network: Network, db: &Path) -> Result<SPV, SPVError> {
        let thread_pool = ThreadPool::new()?;
        let db = Arc::new(Mutex::new(DB::new(db)?));
        let birth = create_tables(db.clone())?;
        let peers = Arc::new(RwLock::new(PeerMap::new()));
        let p2p = Arc::new(P2P::new(user_agent, network, 0, peers.clone(), db.clone(), MAX_PROTOCOL_VERSION));
        let node = Arc::new(Node::new(p2p.clone(), network, db.clone(), true, peers.clone()));
        Ok(SPV{ node, p2p, thread_pool, db: db.clone() })
    }

    /// Initialize the SPV stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    /// The method will start with an empty in-memory database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new_in_memory(user_agent :String, network: Network) -> Result<SPV, SPVError> {
        let thread_pool = ThreadPool::new()?;
        let db = Arc::new(Mutex::new(DB::mem()?));
        let birth = create_tables(db.clone())?;
        let peers = Arc::new(RwLock::new(PeerMap::new()));
        let p2p = Arc::new(P2P::new(user_agent, network, 0, peers.clone(), db.clone(), MAX_PROTOCOL_VERSION));
        let node = Arc::new(Node::new(p2p.clone(), network, db.clone(), true, peers.clone()));
        Ok(SPV{ node, p2p, thread_pool, db: db.clone()})
    }

    /// add a listener of incoming connection requests
    pub fn listen (&self, addr: &SocketAddr) -> Result<(), SPVError> {
        Ok(self.p2p.add_listener(addr)?)
    }

	/// Start the SPV stack. This should be called AFTER registering listener of the ChainWatchInterface,
	/// so they are called as the SPV stack catches up with the blockchain
	/// * peers - connect to these peers at startup (might be empty)
	/// * min_connections - keep connections with at least this number of peers. Peers will be chosen random
	/// from those discovered in earlier runs
    pub fn start (&mut self, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) {
        // read stored headers from db
        // there is no recovery if this fails
        self.node.load_headers().unwrap();

        let p2p = self.p2p.clone();
        let node = self.node.clone();

        // start the task that runs all network communication
        self.thread_pool.spawn (Box::new(future::poll_fn (move |ctx| {
            p2p.run(node.clone(), ctx).unwrap();
            Ok(Async::Ready(()))
        }))).unwrap();

        let connector = self.keep_connected(peers, min_connections, nodns);

        // the task that keeps us connected
        self.thread_pool.run(connector).unwrap();
    }

    fn keep_connected(&self, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Box<Future<Item=(), Error=Never> + Send> {

        let p2p = self.p2p.clone();
        let db = self.db.clone();

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer(PeerSource::Outgoing(addr.clone())));
        }

        struct KeepConnected {
            min_connections: usize,
            connections: Vec<Box<Future<Item=SocketAddr, Error=SPVError> + Send>>,
            db: Arc<Mutex<DB>>,
            p2p: Arc<P2P>,
            dns: Vec<SocketAddr>,
            earlier: HashSet<SocketAddr>,
            nodns: bool
        }

        // this task runs until it runs out of peers
        impl Future for KeepConnected {
            type Item = ();
            type Error = Never;

            fn poll(&mut self, cx: &mut task::Context) -> Poll<Self::Item, Self::Error> {
                // return from this loop with 'pending' if enough peers are connected
                loop {
                    // add further peers from db if needed
                    self.peers_from_db ();
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
                                Some((i, Ok(e)))},
                            Err(e) => {
                                trace!("woke up to peer error");
                                Some((i, Err(e)))
                            },
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
            fn peers_from_db (&mut self) {
                let mut db = self.db.lock().unwrap();

                while self.connections.len()  < self.min_connections {
                    if let Ok(tx) = db.transaction() {
                        // found a peer
                        if let Ok(peer) = tx.get_a_peer(&self.earlier) {
                            // have an address for it
                            // Note: we do not store Tor adresses, so this should always be true
                            if let Ok(ref sock) = peer.socket_addr() {
                                self.earlier.insert(*sock);
                                self.connections.push(self.p2p.add_peer(PeerSource::Outgoing(sock.clone())));
                            } else {
                                break;
                            }
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }

            fn dns_lookup (&mut self) {
                while self.connections.len()  < self.min_connections {
                    if self.dns.len() == 0 {
                        self.dns = dns_seed(self.p2p.network);
                    }
                    if self.dns.len() >0 {
                        let mut rng = thread_rng();
                        let addr = self.dns[(rng.next_u64() as usize) % self.dns.len()];
                        self.connections.push(self.p2p.add_peer(PeerSource::Outgoing(addr)));
                    }
                }
            }
        }

        Box::new(KeepConnected{min_connections, connections: added, db, p2p, dns: Vec::new(), nodns, earlier: HashSet::new() })
	}

    /// Get the connector to higher level appl layers, such as Lightning
    pub fn get_chain_watch_interface (&self) -> Arc<ChainWatchInterface> {
        return self.node.get_chain_watch_interface();
    }

}



/// create tables (if not already there) in the database
fn create_tables(db: Arc<Mutex<DB>>) -> Result<u32, SPVError> {
    let mut db = db.lock().unwrap();
    let tx = db.transaction()?;
    let birth = tx.create_tables()?;
    tx.commit()?;
    Ok(birth)
}