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
//! # Connector to serve a lightning network implementation
//!
//! This implements an interface to higher level applications
//!

use bitcoin::{
    blockdata::{
        block::{Block, BlockHeader},
        transaction::Transaction,
        script::Script,
    },
    network::{
        message::NetworkMessage,
        constants::Network
    }
};

use bitcoin_hashes::sha256d::Hash as Sha256dHash;

#[cfg(feature="lightning")] use lightning::{
    chain::chaininterface::{ChainListener, ChainWatchInterface, ChainWatchInterfaceUtil,ChainError},
    util::logger::{Level, Logger, Record}
};

use p2p::P2PControlSender;

use std::sync::{Arc, Weak, Mutex};

#[cfg(feature="lightning")]
struct LightningLogger{
    level: Level
}

#[cfg(feature="lightning")]
impl Logger for LightningLogger {
    fn log(&self, record: &Record) {
        if self.level >= record.level {
            debug!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
        }
    }
}

pub type SharedLightningConnector = Arc<Mutex<LightningConnector>>;

/// connector to lightning network
pub struct LightningConnector {
    #[cfg(feature="lightning")] util: ChainWatchInterfaceUtil,
    p2p: P2PControlSender
}

impl LightningConnector {
    /// create a connector
    pub fn new (network: Network, p2p: P2PControlSender) -> LightningConnector {
        LightningConnector {
            #[cfg(feature="lightning")] util: ChainWatchInterfaceUtil::new(network, Arc::new(LightningLogger{level: Level::Info})),
            p2p
        }
    }

    /// called by the node if new block added to trunk (longest chain)
    /// this will notify listeners on lightning side
    pub fn block_connected(&self, block: &Block, height: u32) {
        #[cfg(feature="lightning")] self.util.block_connected_with_filtering(block, height)
    }

    /// called by the node if a block is removed from trunk (orphaned from longest chain)
    /// this will notify listeners on lightning side
    pub fn block_disconnected(&self, header: &BlockHeader) {
        #[cfg(feature="lightning")] self.util.block_disconnected(header)
    }

    /// broadcast transaction to all connected peers
    pub fn broadcast (&self, tx: Transaction) {
        #[cfg(feature="lightning")] self.p2p.broadcast(NetworkMessage::Tx(tx))
    }
}

#[cfg(feature="lightning")]
impl ChainWatchInterface for LightningConnector {

    fn install_watch_tx(&self, _txid: &Sha256dHash, _script_pub_key: &Script) {
        unimplemented!()
    }

    /// install a listener to be called with transactions that spend the outpoint
    fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32), out_script: &Script) {
        self.util.install_watch_outpoint(outpoint, out_script)
    }

    /// install a listener to be called for every transaction
    fn watch_all_txn(&self) {
        self.util.watch_all_txn()
    }

    /// install a listener for blocks added to or removed from trunk
    fn register_listener(&self, listener: Weak<ChainListener>) {
        self.util.register_listener(listener)
    }

    fn get_chain_utxo(&self, _genesis_hash: Sha256dHash, _unspent_tx_output_identifier: u64) -> Result<(Script, u64), ChainError> {
        Err(ChainError::NotSupported)
    }
}