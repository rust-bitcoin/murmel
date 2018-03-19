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
//! # Connector to serve a lighning network implementation
//!
//! This implements an interface to higher level applications
//!

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;
use lightning::chain::chaininterface::{ChainListener,ChainWatchInterface, ChainWatchInterfaceUtil};
use node::Broadcaster;
use std::sync::{Weak,Arc};


/// connector to lighning network
pub struct LightningConnector {
    util: ChainWatchInterfaceUtil,
    broadcaster: Arc<Broadcaster>
}

impl LightningConnector {
    /// create a connector
    pub fn new (broadcaster: Arc<Broadcaster>) -> LightningConnector {
        LightningConnector {
            util: ChainWatchInterfaceUtil::new(),
            broadcaster
        }
    }

    /// called by the node if new block added to trunk (longest chain)
    /// this will notify listeners on lighning side
    pub fn block_connected(&self, block: &Block, height: u32) {
        self.util.block_connected_with_filtering(block, height)
    }

    /// called by the node if a block is removed from trunk (orphaned from logest chain)
    /// this will notify listeners on lighning side
    pub fn block_disconnected(&self, header: &BlockHeader) {
        self.util.block_disconnected(header)
    }

    /// return the broadcaster that is able to send to all connected peers
    pub fn get_broadcaster (&self) -> Arc<Broadcaster> {
        return self.broadcaster.clone();
    }
}

impl ChainWatchInterface for LightningConnector {
    /// install a listener to be called with transactions that match the script
    fn install_watch_script(&self, script_pub_key: Script) {
        self.util.install_watch_script(script_pub_key)
    }

    /// install a listener to be called with transactions that spend the outpoint
    fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32)) {
        self.util.install_watch_outpoint(outpoint)
    }

    /// install a listener to be called for every transaction
    fn watch_all_txn(&self) {
        self.util.watch_all_txn()
    }

    /// install a listener for blocks added to or removed from trunk
    fn register_listener(&self, listener: Weak<ChainListener>) {
        self.util.register_listener(listener)
    }
}