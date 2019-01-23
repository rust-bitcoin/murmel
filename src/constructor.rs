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

use configdb::{ConfigDB, SharedConfigDB};
use error::SPVError;
use dispatcher::Dispatcher;
use p2p::{P2P,PeerMessageSender, P2PControl, P2PControlSender, PeerSource};
use chaindb::{ChainDB, SharedChainDB};
use dns::dns_seed;

use bitcoin::{
    network::{
        message::NetworkMessage,
        constants::Network
    },
    blockdata::transaction::Transaction
};

use connector::LightningConnector;
use lightning::chain::chaininterface::BroadcasterInterface;

use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, RwLock, mpsc},
    collections::HashSet
};

use futures::{
    future,
    prelude::*,
    executor::ThreadPool
};
use rand::{thread_rng, RngCore};

const MAX_PROTOCOL_VERSION :u32 = 70001;
// incoming message queue size
const BACK_PRESSURE: usize = 10;

/// a helper class to implement LightningConnector
pub struct Broadcaster {
    p2p: P2PControlSender
}

impl BroadcasterInterface for Broadcaster {
    /// send a transaction to all connected peers
    fn broadcast_transaction(&self, tx: &Transaction) {
        self.p2p.send(P2PControl::Broadcast(NetworkMessage::Tx(tx.clone())))
    }
}

/// The complete stack
pub struct Constructor {
    network: Network,
    user_agent: String,
    configdb: SharedConfigDB,
    chaindb: SharedChainDB,
    listen: Vec<SocketAddr>,
    server: bool,
    /// The Lightning Network connector
    pub connector: Option<Arc<LightningConnector>>
}

impl Constructor {
    /// Initialize the stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer addresses (only tested to work with one local node for now)
    ///      db - file path to data
    /// The method will read previously stored headers from the database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new(user_agent :String, network: Network, path: &Path, server: bool, listen: Vec<SocketAddr>) -> Result<Constructor, SPVError> {
        let configdb = Arc::new(Mutex::new(ConfigDB::new(path)?));
        let chaindb = Arc::new(RwLock::new(ChainDB::new(path, network,server)?));
        create_tables(configdb.clone())?;
        Ok(Constructor { network, user_agent, configdb, chaindb, listen, server, connector: None })
    }

    /// Initialize the stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    /// The method will start with an empty in-memory database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new_in_memory(user_agent :String, network: Network, server: bool, listen: Vec<SocketAddr>) -> Result<Constructor, SPVError> {
        let configdb = Arc::new(Mutex::new(ConfigDB::mem()?));
        let chaindb = Arc::new(RwLock::new(ChainDB::mem( network,server)?));
        create_tables(configdb.clone())?;
        Ok(Constructor { network, user_agent, configdb, chaindb, listen, server, connector: None })
    }

	/// Run the SPV stack. This should be called AFTER registering listener of the ChainWatchInterface,
	/// so they are called as the SPV stack catches up with the blockchain
	/// * peers - connect to these peers at startup (might be empty)
	/// * min_connections - keep connections with at least this number of peers. Peers will be randomly chosen
	/// from those discovered in earlier runs
    pub fn run(&mut self, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Result<(), SPVError>{

        let (to_dispatcher, from_p2p) = mpsc::sync_channel(BACK_PRESSURE);

        let (p2p, p2p_control) =
            P2P::new(self.user_agent.clone(), self.network, 0, MAX_PROTOCOL_VERSION, PeerMessageSender::new(to_dispatcher));

        let lightning = Arc::new(LightningConnector::new(self.network, Arc::new(Broadcaster { p2p: p2p_control.clone() })));
        self.connector = Some(lightning.clone());

        let dispatcher =
            Dispatcher::new(self.network, self.configdb.clone(), self.chaindb.clone(), self.server, lightning, p2p_control.clone(), from_p2p);

        dispatcher.init().unwrap();

        for addr in &self.listen {
            p2p_control.send(P2PControl::Bind(addr.clone()));
        }

        let p2p2 = p2p.clone();
        let p2p_task = Box::new(future::poll_fn (move |ctx| {
            p2p2.run(ctx).unwrap();
            Ok(Async::Ready(()))
        }));

        let mut thread_pool = ThreadPool::new()?;

        // start the task that runs all network communication
        thread_pool.spawn (p2p_task).unwrap();

        // the task that keeps us connected
        // note that this call does not return
        thread_pool.run(self.keep_connected(p2p, peers, min_connections, nodns)).unwrap();
        Ok(())
    }

    fn keep_connected(&self, p2p: Arc<P2P>, peers: Vec<SocketAddr>, min_connections: usize, nodns: bool) -> Box<Future<Item=(), Error=Never> + Send> {

        let db = self.configdb.clone();

        // add initial peers if any
        let mut added = Vec::new();
        for addr in &peers {
            added.push(p2p.add_peer(PeerSource::Outgoing(addr.clone())));
        }

        struct KeepConnected {
            min_connections: usize,
            connections: Vec<Box<Future<Item=SocketAddr, Error=SPVError> + Send>>,
            db: Arc<Mutex<ConfigDB>>,
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
                            // Note: we do not store Tor addresses, so this should always be true
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
}



/// create tables (if not already there) in the database
fn create_tables(db: Arc<Mutex<ConfigDB>>) -> Result<(), SPVError> {
    let mut db = db.lock().unwrap();
    let mut tx = db.transaction()?;
    tx.create_tables()?;
    tx.commit()?;
    Ok(())
}