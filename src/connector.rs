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

use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::hash::Sha256dHash;
use lightning::chain::chaininterface::{ChainListener, ChainWatchInterface, ChainWatchInterfaceUtil};
use node::Broadcaster;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Weak;

/// implements the ChainWatchInterface required by rust-lightning projec
pub struct LightningConnector {
    util: ChainWatchInterfaceUtil,
    watch: AtomicUsize,
    broadcaster: Broadcaster,
}

impl LightningConnector {
    pub fn new(broadcaster: Broadcaster) -> LightningConnector {
        LightningConnector {
            util: ChainWatchInterfaceUtil::new(),
            watch: AtomicUsize::new(1),
            broadcaster,
        }
    }

    pub fn block_connected(&self, block: &Block, height: u32) {
        let mut watch = self.watch.load(Ordering::Relaxed);
        let mut last_seen = 0;
        // re-scan if new watch added during previous scan
        while last_seen != watch {
            let mut matched = Vec::new();
            let mut matched_index = Vec::new();
            for (index, transaction) in block.txdata.iter().enumerate() {
                if self.util.does_match_tx(transaction) {
                    matched.push(transaction);
                    matched_index.push(index as u32);
                }
            }
            last_seen = watch;
            self.util.do_call_block_connected(&block.header, height, matched.as_slice(), matched_index.as_slice());
            watch = self.watch.load(Ordering::Relaxed);
        }
    }

    pub fn block_disconnected(&self, header: &BlockHeader) {
        self.util.do_call_block_disconnected(header);
    }
}

impl ChainWatchInterface for LightningConnector {
    fn install_watch_script(&self, script_pub_key: Script) {
        self.util.install_watch_script(script_pub_key);
        self.watch.fetch_add(1, Ordering::Relaxed);
    }

    fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32)) {
        self.util.install_watch_outpoint(outpoint);
        self.watch.fetch_add(1, Ordering::Relaxed);
    }

    fn watch_all_txn(&self) {
        self.util.watch_all_txn();
        self.watch.fetch_add(1, Ordering::Relaxed);
    }

    fn broadcast_transaction(&self, tx: &Transaction) {
        self.broadcaster.broadcast(tx).is_err(); // TODO: what about an error here?
    }

    fn register_listener(&self, listener: Weak<ChainListener>) {
        self.util.register_listener(listener);
    }
}