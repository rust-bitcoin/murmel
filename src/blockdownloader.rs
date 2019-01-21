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
//! # Download Blocks
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
use rand::{RngCore, thread_rng};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, SystemTime},
};

pub struct BlockDownloader {
    network: Network,
    chaindb: SharedChainDB,
    p2p: P2PControlSender,
    tasks: HashMap<Arc<Sha256dHash>, (PeerId, u64)>,
    peers: HashMap<PeerId, Option<HashSet<Arc<Sha256dHash>>>>,
    last_seen: HashMap<PeerId, u64>,
}


// pollfrequency in millisecs
const POLL: u64 = 1000;
// a block should arrive within this timeout in seconds
const BLOCK_TIMEOUT: u64 = 60;
// download in chunks of n blocks
const CHUNK: usize = 1000;

impl BlockDownloader {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::channel();

        let mut blockdownloader = BlockDownloader { network, chaindb, p2p, tasks: HashMap::new(), peers: HashMap::new(), last_seen: HashMap::new() };

        thread::spawn(move || { blockdownloader.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        let genesis_hash = genesis_block(self.network).header.bitcoin_hash();
        let mut rng = thread_rng();
        loop {
            // wait some time for incoming block messages, process them if available
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(POLL)) {
                match msg {
                    PeerMessage::Connected(pid) => { self.peers.insert(pid, None); },
                    PeerMessage::Disconnected(pid) => {
                        self.peers.remove(&pid);
                        let remove = self.tasks.iter()
                            .filter_map(|(h, (peer, _))| {
                                if *peer == pid { Some(h.clone()) } else { None } }
                            ).collect::<Vec<_>>();
                        for h in remove {
                            self.tasks.remove(&*h);
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

            // check for new work
            // what is missing might change through new header or even reorg

            // can not work if no peers are connected
            if self.peers.len() > 0 {
                // compute the list of missing blocks
                let mut missing = Vec::new();
                // missing if not yet asked for and not yet stored
                if self.tasks.is_empty() {
                    let chaindb = self.chaindb.read().unwrap();
                    for header in chaindb.iter_trunk_to_genesis() {
                        if header.block.is_none() {
                            missing.push(header.bitcoin_hash());
                        }
                    }
                }

                if !missing.is_empty() {
                    // insert genesis if missing
                    if *missing.last().unwrap() == Sha256dHash::default() {
                        let mut chaindb = self.chaindb.write().unwrap();
                        chaindb.store_block(&genesis_block(self.network)).expect("can not store genesis block");
                        chaindb.batch().expect("can not store genesis block");
                        let len = missing.len();
                        missing.truncate(len - 1);
                    }

                    debug!("missing {} blocks", missing.len());
                    // download in ascending block order
                    missing.reverse();

                    // pick a random peer
                    let pl = self.peers.len();
                    let peer_id = self.peers.keys().collect::<Vec<_>>()[rng.next_u32() as usize % pl].clone();

                    let todo = missing.iter().filter_map(|s| {
                        // download if
                        if let Some((peer, started)) = self.tasks.get(s).clone() {
                            // already asked for and ...
                            if *peer != peer_id {
                                // this is not the same peer we asked before
                                if started + BLOCK_TIMEOUT < Self::now() {
                                    // asked for longer than timeout
                                    if let Some(last) = self.last_seen.get(peer) {
                                        // and the peer did not deliver any other blocks in the meanwhile
                                        if last + BLOCK_TIMEOUT < Self::now() {
                                            // ban the peer
                                            self.p2p.send(P2PControl::Ban(*peer, 100));
                                            debug!("too slow delivering blocks, ban peer={}", peer);
                                            // download
                                            return Some(s.clone());
                                        }
                                    }
                                }
                            }
                            // do not download
                            None
                        } else {
                            // download
                            Some(s.clone())
                        }
                    }).collect::<Vec<_>>();

                    let mut some = todo.as_slice().chunks(CHUNK);
                    // take a chunk of the work
                    if let Some(need) = some.next() {
                        // and send it to peer
                        if let Some(ref mut pe) = self.peers.entry(peer_id).or_insert(Some(HashSet::new())) {
                            for id in need {
                                let id = Arc::new(id.clone());
                                pe.insert(id.clone());
                                self.tasks.insert(id, (peer_id, Self::now()));
                            }
                        }
                        let invs = need.iter().map(|s| { Inventory { inv_type: InvType::WitnessBlock, hash: s.clone() } }).collect::<Vec<_>>();
                        debug!("asking {} blocks peer={}", invs.len(), peer_id);
                        self.p2p.send(P2PControl::Send(peer_id, NetworkMessage::GetData(invs)));
                    }
                }
            }
        }
    }

    fn block(&mut self, pid: PeerId, block: &Block) {
        let mut chaindb = self.chaindb.write().unwrap();
        debug!("storing block {}", block.bitcoin_hash());
        chaindb.store_block(block).expect(format!("could not store block {}", block.bitcoin_hash()).as_str());
        if let Some((peer_id, _)) = self.tasks.remove(&block.bitcoin_hash()) {
            if let Entry::Occupied(ref mut peer_tasks) = self.peers.entry(peer_id) {
                if let Some(ref mut set) = peer_tasks.get_mut() {
                    set.remove(&block.bitcoin_hash());
                }
            }
            self.last_seen.insert(pid, Self::now());
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }
}