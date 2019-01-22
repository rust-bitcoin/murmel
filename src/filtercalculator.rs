//
// Copyright 2018-19 Tamas Blummer
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
//! # Download all Blocks calculate UTXO and BIP158 filter
//!

use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::Block,
        constants::genesis_block,
    },
    network::{
        constants::Network,
        message::NetworkMessage,
        message_blockdata::{Inventory, InvType},
    },
    util::hash::Sha256dHash,
};
use chaindb::SharedChainDB;
use configdb::SharedConfigDB;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};

use std::{
    hash::{Hasher, Hash},
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, SystemTime},
    cmp::Ordering
};


pub struct FilterCalculator {
    network: Network,
    chaindb: SharedChainDB,
    p2p: P2PControlSender,
    peer: Option<PeerId>,
    peers: HashSet<PeerId>,
    tasks: HashSet<Sha256dHash>,
    last_seen: u64
}


// pollfrequency in millisecs
const POLL: u64 = 1000;
// a block should arrive within this timeout in seconds
const BLOCK_TIMEOUT: u64 = 60;
// download in chunks of n blocks
const CHUNK: usize = 1000;

impl FilterCalculator {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::channel();

        let mut filtercalculator = FilterCalculator { network, chaindb, p2p, peer: None, tasks: HashSet::new(), peers: HashSet::new(), last_seen: Self::now() };

        thread::spawn(move || { filtercalculator.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        loop {
            if self.peer.is_some() && !self.tasks.is_empty() && self.last_seen  + BLOCK_TIMEOUT < Self::now () {
                let peer = self.peer.unwrap();
                debug!("Too slow delivering blocks disconnect peer={}", peer);
                self.p2p.send(P2PControl::Ban(peer, 100));
                self.last_seen = Self::now();
            }
            // wait some time for incoming block messages, process them if available
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(POLL)) {
                match msg {
                    PeerMessage::Connected(pid) => {
                        if self.peer.is_none() {
                            debug!("block download from peer={}", pid);
                            self.peer = Some(pid);
                        }
                        self.peers.insert(pid);
                    },
                    PeerMessage::Disconnected(pid) => {
                        self.peers.remove(&pid);
                        if self.peer.is_some() {
                            if self.peer.unwrap() == pid {
                                self.tasks.clear();
                                if let Some(new_peer) = self.peers.iter().next() {
                                    self.peer = Some(*new_peer);
                                    debug!("block download from peer={}", *new_peer);
                                }
                                else {
                                    self.peer = None;
                                }
                            }
                        }
                    },
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Block(block) => {
                                self.block(pid, &block);
                            }
                            _ => {}
                        }
                    }
                }
            }

            // unwind utxo if no longer on trunk
            {
                let mut chaindb = self.chaindb.write().unwrap();
                if let Some(utxo_tip) = chaindb.utxo_tip().expect("can not read utxo tip") {
                    while chaindb.is_on_trunk(&utxo_tip) == false {
                        chaindb.unwind_utxo(&utxo_tip).expect("can not unwind utxo");
                    }
                }
            }

            // check for new work
            // what is missing might change through new header or even reorg

            // can not work if no peer is connected
            if let Some(peer) = self.peer {
                // compute the list of missing blocks
                // missing that is on trunk, we do not yet have and also not yet asked for
                let mut missing = Vec::new();

                {
                    let chaindb = self.chaindb.read().unwrap();
                    for header in chaindb.iter_trunk_to_genesis() {
                        let id = header.bitcoin_hash();
                        if header.block.is_none() && !self.tasks.contains(&id) {
                            missing.push(id);
                        }
                    }
                }
                if missing.last().is_some() && *missing.last().unwrap () == genesis_block(self.network).header.bitcoin_hash() {
                    let mut chaindb = self.chaindb.write().unwrap();
                    chaindb.store_block(&genesis_block(self.network)).expect("can not store genesis block");
                    chaindb.batch().expect("can not store genesis block");
                    let len = missing.len();
                    missing.truncate(len - 1);
                }

                missing.reverse();

                for chunk in missing.as_slice().chunks(CHUNK) {
                    let invs = chunk.iter().map(|s| { Inventory { inv_type: InvType::WitnessBlock, hash: s.clone() } }).collect::<Vec<_>>();
                    debug!("asking {} blocks from peer={}", invs.len(), peer);
                    self.p2p.send(P2PControl::Send(peer, NetworkMessage::GetData(invs)));
                }
                missing.iter().for_each(|id| { self.tasks.insert(id.clone());});
            }
        }
    }

    fn block(&mut self, pid: PeerId, block: &Block) {
        if self.tasks.remove(&block.bitcoin_hash()) {
            self.last_seen = Self::now();
            let mut chaindb = self.chaindb.write().unwrap();
            chaindb.store_block(block).expect(format!("could not store block {}", block.bitcoin_hash()).as_str());
            debug!("stored block {}", block.bitcoin_hash());
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }
}