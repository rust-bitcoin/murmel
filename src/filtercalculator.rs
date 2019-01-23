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
use chaindb::{SharedChainDB, ChainDB, StoredHeader};
use blockfilter::BlockFilter;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};

use hammersbald::PRef;

use std::{
    collections::HashSet,
    sync::{mpsc, RwLockWriteGuard},
    thread,
    time::{Duration, SystemTime}
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
// channel size
const BACK_PRESSURE: usize = 10;

impl FilterCalculator {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(BACK_PRESSURE);

        let mut filtercalculator = FilterCalculator { network, chaindb, p2p, peer: None, tasks: HashSet::new(), peers: HashSet::new(), last_seen: Self::now() };

        thread::spawn(move || { filtercalculator.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        let genesis = genesis_block(self.network);
        let mut re_check = true;
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
                            self.tasks.clear();
                            self.peer = Some(pid);
                            re_check = true;
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
                                    re_check = true;
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
                                re_check = true;
                                self.block(pid, &block);
                            },
                            NetworkMessage::Ping(_) => {
                                re_check = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // unwind utxo if no longer on trunk
            {
                let mut chaindb = self.chaindb.write().unwrap();
                if let Some(mut utxo_tip) = chaindb.utxo_tip().expect("can not read utxo tip") {
                    while chaindb.is_on_trunk(&utxo_tip) == false {
                        debug!("unwind utxo {}", utxo_tip);
                        utxo_tip = chaindb.unwind_utxo(&utxo_tip).expect("can not unwind utxo");
                    }
                    // roll forward as far as blocks are already known
                    let forward_path = chaindb.iter_to_tip(&utxo_tip).collect::<Vec<_>>();
                    for forward in forward_path {
                        if let Some(header) = chaindb.get_header(&forward) {
                            if let Some(block_ref) = header.block {
                                if let Some(block) = chaindb.fetch_block(header.height).expect("can not read blocks") {
                                    let block = Block{header: header.header, txdata: block.txdata};
                                    debug!("fast forward utxo {}", utxo_tip);
                                    Self::forward_utxo(&mut chaindb, block_ref, &block, &header);
                                }
                                else {
                                    panic!("corrupted db, header does not point to a block {}", header.header.bitcoin_hash());
                                }
                            }
                            else {
                                break;
                            }
                        }
                    }
                    chaindb.batch().expect("can not batch UTXO store");
                }

            }

            // check for new work
            // what is missing might change through new header or even reorg

            // can not work if no peer is connected
            if let Some(peer) = self.peer {
                if self.tasks.is_empty () && re_check {
                    re_check = false;
                    // compute the list of missing blocks
                    // missing that is on trunk, we do not yet have and also not yet asked for
                    let mut missing = Vec::new();

                    {
                        debug!("calculate missing blocks...");
                        let chaindb = self.chaindb.read().unwrap();
                        for header in chaindb.iter_trunk_to_genesis() {
                            let id = header.bitcoin_hash();
                            if header.block.is_none() && !self.tasks.contains(&id) {
                                missing.push(id);
                            }
                        }
                        debug!("missing {} blocks", missing.len());
                    }
                    if missing.last().is_some() && *missing.last().unwrap() == genesis.bitcoin_hash() {
                        let mut chaindb = self.chaindb.write().unwrap();
                        if chaindb.utxo_tip().expect("can not read utxo tip").is_none() {
                            let block_ref = chaindb.store_block(&genesis).expect("can not store genesis block");
                            let filter = BlockFilter::compute_wallet_filter(&genesis, chaindb.get_utxo_accessor(&genesis)).expect("can not compute filter");
                            chaindb.store_known_filter(&genesis.bitcoin_hash(), &Sha256dHash::default(), filter.content).expect("failed to store filter");
                            chaindb.utxo_block(block_ref).expect("failed to apply block to UTXO");
                            chaindb.batch().expect("can not store genesis block");
                            let len = missing.len();
                            missing.truncate(len - 1);
                        }
                    }

                    missing.reverse();

                    if let Some(chunk) = missing.as_slice().chunks(CHUNK).next() {
                        let invs = chunk.iter().map(|s| { Inventory { inv_type: InvType::WitnessBlock, hash: s.clone() } }).collect::<Vec<_>>();
                        debug!("asking {} blocks from peer={}", invs.len(), peer);
                        self.p2p.send(P2PControl::Send(peer, NetworkMessage::GetData(invs)));
                        chunk.iter().for_each(|id| { self.tasks.insert(id.clone()); });
                    }
                }
            }
        }
    }

    fn block(&mut self, _: PeerId, block: &Block) {
        if self.tasks.remove(&block.bitcoin_hash()) {
            self.last_seen = Self::now();
            let block_id = block.bitcoin_hash();
            let mut chaindb = self.chaindb.write().unwrap();
            if let Some(header) = chaindb.get_header(&block_id) {
                debug!("store block  {} {}", header.height, block_id);
                let block_ref = chaindb.store_block(block).expect(format!("could not store block {}", block_id).as_str());
                Self::forward_utxo(&mut chaindb, block_ref, block, &header);
            }
            // batch sometimes
            if self.tasks.is_empty () {
                chaindb.batch().expect("can not batch on chain db");
            }
        }
        else {
            debug!("received unwanted block {}", block.bitcoin_hash());
        }
    }

    fn forward_utxo (chaindb: &mut RwLockWriteGuard<ChainDB>, block_ref: PRef, block :&Block, header: &StoredHeader) {
        let block_id = block.bitcoin_hash();
        if let Some(utxo_tip) = chaindb.utxo_tip().expect("can not read utxo tip") {
            if block.header.prev_blockhash == utxo_tip {
                if let Some(prev_filter) = chaindb.get_block_filter(&block.header.prev_blockhash) {
                    let filter = BlockFilter::compute_wallet_filter(&block, chaindb.get_utxo_accessor(block)).expect("can not compute filter");
                    debug!("store filter {} {} size: {}", header.height, block_id, filter.content.len());
                    chaindb.store_known_filter(&block_id, &prev_filter.bitcoin_hash(), filter.content).expect("failed to store filter");
                }
                debug!("store utxo   {} {}", header.height, block_id);
                chaindb.utxo_block(block_ref).expect("failed to apply block to UTXO");
            }
        }
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }
}