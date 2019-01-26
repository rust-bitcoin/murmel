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
use blockfilter::BlockFilter;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use error::SPVError;
use blockfilter::{COIN_FILTER, SCRIPT_FILTER};

use std::{
    collections::HashSet,
    sync::mpsc,
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
const POLL: u64 = 100;
// a block should arrive within this timeout in seconds
const BLOCK_TIMEOUT: u64 = 300;
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
                                self.block(pid, &block).expect("block store failed");
                            },
                            NetworkMessage::Ping(_) => {
                                re_check = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            // check for new work
            // what is missing might change through new header or even reorg
            if re_check {
                self.download().expect("download failed");
                re_check = false;
            }

        }
    }

    fn download (&mut self) -> Result<(), SPVError> {
        let genesis = genesis_block(self.network);
        // can not work if no peer is connected
        if let Some(peer) = self.peer {
            if self.tasks.is_empty () {
                // compute the list of missing blocks
                // missing that is on trunk, we do not yet have and also not yet asked for
                let mut missing = Vec::new();

                {
                    debug!("calculate missing blocks...");
                    let chaindb = self.chaindb.read().unwrap();
                    for header in chaindb.iter_trunk_rev(None) {
                        let id = header.bitcoin_hash();
                        if header.block.is_none() && !self.tasks.contains(&id) {
                            missing.push(id);
                        }
                    }
                    debug!("missing {} blocks", missing.len());
                }
                if missing.last().is_some() && *missing.last().unwrap() == genesis.bitcoin_hash() {
                    let mut chaindb = self.chaindb.write().unwrap();
                    let block_ref = chaindb.store_block(&genesis)?;
                    let script_filter = BlockFilter::compute_script_filter(&genesis, chaindb.get_script_accessor(&genesis))?;
                    let coin_filter = BlockFilter::compute_coin_filter(&genesis)?;
                    chaindb.store_known_filter(&Sha256dHash::default(), &Sha256dHash::default(), &script_filter, &coin_filter)?;
                    chaindb.cache_scripts(&genesis, 0);
                    chaindb.batch()?;
                    let len = missing.len();
                    missing.truncate(len - 1);
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
        Ok(())
    }

    fn block(&mut self, peer: PeerId, block: &Block) -> Result<(), SPVError> {
        if self.tasks.remove(&block.bitcoin_hash()) {
            self.last_seen = Self::now();
            let block_id = block.bitcoin_hash();
            let mut chaindb = self.chaindb.write().unwrap();
            if let Some(header) = chaindb.get_header(&block_id) {
                debug!("store block  {} {}", header.height, block_id);
                if block.check_merkle_root() && block.check_witness_commitment() {
                    chaindb.store_block(block)?;
                    chaindb.cache_scripts(block, header.height);
                    if let Some(prev_script) = chaindb.get_block_filter(&block.header.prev_blockhash, SCRIPT_FILTER) {
                        if let Some(prev_coin) = chaindb.get_block_filter(&block.header.prev_blockhash, COIN_FILTER) {
                            let script_filter = BlockFilter::compute_script_filter(&block, chaindb.get_script_accessor(block))?;
                            let coin_filter = BlockFilter::compute_coin_filter(&block)?;
                            debug!("store filter {} {} size: {} {}", header.height, block_id, script_filter.content.len(), coin_filter.content.len());
                            chaindb.store_known_filter(&prev_script.bitcoin_hash(), &prev_coin.bitcoin_hash(), &script_filter, &coin_filter)?;
                            // let client know we have a new block
                            self.p2p.send(P2PControl::Broadcast(NetworkMessage::Inv(vec!(Inventory{inv_type: InvType::Block, hash:block_id}))));
                        }
                    }
                }
                else {
                    debug!("received tampered block, banning peer={}", peer);
                    self.p2p.send(P2PControl::Ban(peer, 100));
                }
            }
            // batch sometimes
            if self.tasks.is_empty () {
                chaindb.batch()?;
            }
        }
        else {
            debug!("received unwanted block {}", block.bitcoin_hash());
        }
        Ok(())
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }
}