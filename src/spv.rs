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
use dispatcher::Dispatcher;
use error::SPVError;
use lightning::chain::chaininterface::ChainWatchInterface;
use node::Node;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::executor::current_thread;
use lighningconnector::LightningConnector;


/// The complete SPV stack
pub struct SPV{
	node: Arc<Node>,
	dispatcher: Dispatcher
}

impl SPV {
    /// Initialize the SPV stack and return a ChainWatchInterface
    /// Set
    ///      network - main or testnet
    ///      bootstrap - peer adresses (only tested to work with one local node for now)
    ///      db - file path to store the headers and blocks database
    /// The method will read previously stored headers from the database and sync up with the peers
    /// then serve the returned ChainWatchInterface
    pub fn new(network: Network, db: &Path) -> Result<SPV, SPVError> {
        let mut db = DB::new(db)?;
        create_tables(&mut db)?;
        Ok(SPV{ node:  Arc::new(Node::new(network, db)), dispatcher: Dispatcher::new(network, 0)})
    }

	/// Start the SPV stack. This should be called AFTER registering listener of the ChainWatchInterface,
	/// so they are called as the SPV stack catches up with the blockchain
	pub fn run (&self, peers: Vec<SocketAddr>) -> Result<(), SPVError> {
		self.node.load_headers()?;
		let cnode = self.node.clone();
		current_thread::run (|_| {
			current_thread::spawn(self.dispatcher.run(cnode, peers))
		});
		Ok(())
	}

    /// Get the connector to higher level appl layers, such as Lightning
    pub fn get_chain_watch_interface (&self) -> Arc<ChainWatchInterface> {
        return self.node.get_chain_watch_interface();
    }
}

/// create tables (if not already there) in the database
fn create_tables(db: &mut DB) -> Result<(), SPVError> {
    let tx = db.transaction()?;
    tx.create_tables()?;
    tx.commit()?;
    Ok(())
}