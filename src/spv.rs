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
use std::sync::{Arc, Mutex};

/// The complete SPV stack
pub struct SPV{
	node: Arc<Node>,
	p2p: Arc<P2P>
}

impl SPV {
    /// Initialize the SPV stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    ///      db - file path to store the headers and blocks database
    ///      birth - unix time stamp. We are interested in transactions only after this birth day
    /// The method will read previously stored headers from the database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new(user_agent :String, network: Network, db: &Path) -> Result<SPV, SPVError> {
        let mut db = DB::new(db)?;
        let birth = create_tables(&mut db)?;
        let p2p = Arc::new(P2P::new(user_agent, network, 0));
        let node = Arc::new(Node::new(p2p.clone(), network, Arc::new(Mutex::new(db)),
                                      birth));
        Ok(SPV{ node, p2p})
    }

    /// Initialize the SPV stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    ///      birth - unix time stamp. We are interested in transactions only after this birth day
    /// The method will start with an empty in-memory database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new_in_memory(user_agent :String, network: Network) -> Result<SPV, SPVError> {
        let mut db = DB::mem()?;
        let birth = create_tables(&mut db)?;
        let p2p = Arc::new(P2P::new(user_agent, network, 0));
        let node = Arc::new(Node::new(p2p.clone(), network, Arc::new(Mutex::new(db)),
                                      birth));
        Ok(SPV{ node, p2p})
    }

	/// Start the SPV stack. This should be called AFTER registering listener of the ChainWatchInterface,
	/// so they are called as the SPV stack catches up with the blockchain
	/// * peers - connect to these peers at startup (might be empty)
	/// * min_connections - initiate connections the at least this number of peers. Peers will be chosen random
	/// from those discovered in earlier runs
	pub fn run (&self, peers: Vec<SocketAddr>, _min_connections: u16) -> Result<(), SPVError> {
		self.node.load_headers()?;
        for addr in &peers {
            self.p2p.add_peer(addr)?;
        }
        self.p2p.run(self.node.clone())?;
		Ok(())
	}

    /// Get the connector to higher level appl layers, such as Lightning
    pub fn get_chain_watch_interface (&self) -> Arc<ChainWatchInterface> {
        return self.node.get_chain_watch_interface();
    }
}

/// create tables (if not already there) in the database
fn create_tables(db: &mut DB) -> Result<u32, SPVError> {
    let tx = db.transaction()?;
    let birth = tx.create_tables()?;
    tx.commit()?;
    Ok(birth)
}