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

use lightning::{
    chain::chaininterface::{ChainListener, ChainWatchInterface, ChainWatchInterfaceUtil,ChainError},
    util::logger::{Level, Logger, Record}
};
use log::debug;

use crate::downstream::Downstream;

use crate::p2p::P2PControlSender;

use std::sync::{Arc, Weak, Mutex};

struct LightningLogger {
    level: Level
}

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
    util: ChainWatchInterfaceUtil,
    p2p: P2PControlSender<NetworkMessage>,
}

impl Downstream for LightningConnector {
    /// called by the node if new block added to trunk (longest chain)
    /// this will notify listeners on lightning side
    fn block_connected(&mut self, _block: &Block, _height: u32) {
        // TODO FIX
        // self.util.block_connected(block, height)
    }

    fn header_connected(&mut self, _block: &BlockHeader, _height: u32) {}

    /// called by the node if a block is removed from trunk (orphaned from longest chain)
    /// this will notify listeners on lightning side
    fn block_disconnected(&mut self, _header: &BlockHeader) {
        // TODO FIX
        // self.util.block_disconnected(header)
    }
}

impl LightningConnector {
    /// create a connector
    pub fn new(network: Network, p2p: P2PControlSender<NetworkMessage>) -> LightningConnector {
        LightningConnector {
            util: ChainWatchInterfaceUtil::new(network, Arc::new(LightningLogger{level: Level::Info})),
            p2p
        }
    }

    /// broadcast transaction to all connected peers
    pub fn broadcast(&self, tx: Transaction) {
        self.p2p.broadcast(NetworkMessage::Tx(tx))
    }
}

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

    // TODO FIX
    /// install a listener for blocks added to or removed from trunk
    // fn register_listener(&self, listener: Weak<ChainListener>) {
    //     self.util.register_listener(listener)
    // }

    fn get_chain_utxo(&self, genesis_hash: Sha256dHash, unspent_tx_output_identifier: u64, ) -> Result<(Script, u64), ChainError> {
        self.util.get_chain_utxo(genesis_hash, unspent_tx_output_identifier)
    }

    fn filter_block<'a>(&self, block: &'a Block) -> (Vec<&'a Transaction>, Vec<u32>) {
        self.util.filter_block(block)
    }

    fn reentered(&self) -> usize {
        self.util.reentered()
    }
}
