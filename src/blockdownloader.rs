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
//! # Download Blocks
//!

use configdb::SharedConfigDB;
use chaindb::SharedChainDB;
use p2p::{PeerMessageReceiver, P2PControlSender, PeerId, PeerMessage, PeerMessageSender};

use bitcoin::{
    BitcoinHash,
    blockdata::block::Block,
    network::message::NetworkMessage,
    util::hash::Sha256dHash
};

use rand::{RngCore, thread_rng};

use std::{
    thread,
    time::Duration,
    collections::HashMap,
    sync::{Arc, mpsc},
};

pub struct BlockDownloader {
    chaindb: SharedChainDB,
    p2p: P2PControlSender,
    tasks: HashMap<Arc<Sha256dHash>, PeerId>,
    peers: HashMap<PeerId, Option<Vec<Arc<Sha256dHash>>>>
}

impl BlockDownloader {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::channel();

        let mut blockdownloader = BlockDownloader { chaindb, p2p, tasks: HashMap::new(), peers: HashMap::new() };

        thread::spawn(move || { blockdownloader.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid) => { self.peers.insert(pid, None); },
                    PeerMessage::Disconnected(pid) => { self.peers.remove(&pid); },
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Block(block) => {
                                self.block(&block);
                            }
                            _ => {}
                        }
                    }
                }
            }
            if self.peers.len() > 0 {
                let mut rng = thread_rng();

                let chaindb = self.chaindb.read().unwrap();
                if let Some(tip) = chaindb.tip() {
                    let mut h = tip.bitcoin_hash();
                    while let Some(header) = chaindb.get_header(&h) {
                        if self.tasks.get(&h).is_none() && !chaindb.has_block(&h).expect(format!("can not read block {}", h).as_str()) {
                            let peer = self.peers.keys().collect::<Vec<_>>()[rng.next_u32() as usize % self.peers.len()].clone();
                            if let Some(assignments) = self.peers.entry(peer).or_insert(Some(Vec::new())) {
                                assignments.push(Arc::new(h));
                            }
                        }
                        h = header.header.prev_blockhash;
                        if h == Sha256dHash::default() {
                            break;
                        }
                    }
                }
            }
        }
    }

    fn block(&mut self, block: &Block) {
        let mut chaindb = self.chaindb.write().unwrap();
        debug!("storing block {}", block.bitcoin_hash());
        if let Err(e) = chaindb.store_block(block) {
            error!("can not store block {}: {}", block.bitcoin_hash(), e);
        }
    }
}