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
use p2p::{PeerMessageReceiver, P2PControlSender, P2PControl, PeerId, PeerMessage, PeerMessageSender};

use bitcoin::{
    BitcoinHash,
    blockdata::{
        constants::genesis_block,
        block::Block,
    },
    network::{
        constants::Network,
        message::NetworkMessage,
        message_blockdata::{InvType, Inventory},
    },
    util::hash::Sha256dHash
};

use rand::{RngCore, thread_rng};

use std::{
    thread,
    time::Duration,
    collections::{HashSet, HashMap},
    sync::{Arc, mpsc},
};

pub struct BlockDownloader {
    network: Network,
    chaindb: SharedChainDB,
    p2p: P2PControlSender,
    tasks: HashMap<Arc<Sha256dHash>, PeerId>,
    peers: HashMap<PeerId, Option<Vec<Arc<Sha256dHash>>>>,
    todo: Option<HashSet<Arc<Sha256dHash>>>
}

impl BlockDownloader {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::channel();

        let mut blockdownloader = BlockDownloader { network, chaindb, p2p, tasks: HashMap::new(), peers: HashMap::new(), todo: None };

        thread::spawn(move || { blockdownloader.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        let genesis_hash = genesis_block(self.network).header.bitcoin_hash();
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid) => { self.peers.insert(pid, None); },
                    PeerMessage::Disconnected(pid) => { self.peers.remove(&pid); },
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Block(block) => {
                                self.block(&block);
                            },
                            NetworkMessage::Inv(inventory) => {
                                self.inv(inventory);
                            }
                            _ => {}
                        }
                    }
                }
            }
            if self.peers.len() > 0 {
                if self.todo.is_none() {
                    self.todo = Some(HashSet::new());
                    let chaindb = self.chaindb.read().unwrap();
                    for header in chaindb.iter_trunk_to_genesis() {
                        if header.block.is_none() {
                            if let Some(ref mut todo) = self.todo {
                                todo.insert(Arc::new(header.bitcoin_hash()));
                            }
                        }
                    }
                }
                if let Some(ref mut todo) = self.todo {
                    if todo.contains(&genesis_hash) {
                        let mut chaindb = self.chaindb.write().unwrap();
                        chaindb.store_block(&genesis_block(self.network)).expect("can not store genesis block");
                        todo.remove(&genesis_hash);
                    }
                    let peer_id = self.peers.keys().last().unwrap();
                    for need in todo.iter() {
                        self.p2p.send(P2PControl::Send(*peer_id,
                                                       NetworkMessage::GetData(vec!(Inventory { inv_type: InvType::WitnessBlock, hash: **need }))))
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

    fn inv(&mut self, inventory: Vec<Inventory>) {
        for i in inventory {
            if i.inv_type == InvType::Block {
                if let Some(ref mut todo) = self.todo {
                    todo.insert(Arc::new(i.hash));
                }
            }
        }
    }
}