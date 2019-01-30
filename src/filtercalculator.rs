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
use error::MurmelError;
use blockfilter::{COIN_FILTER, SCRIPT_FILTER};
use timeout::{ExpectedReply, SharedTimeout};

use std::{
    collections::HashSet,
    sync::mpsc,
    thread,
    time::Duration
};


pub struct FilterCalculator {
    network: Network,
    chaindb: SharedChainDB,
    p2p: P2PControlSender,
    peer: Option<PeerId>,
    peers: HashSet<PeerId>,
    want: HashSet<Sha256dHash>,
    missing: Vec<Sha256dHash>,
    timeout: SharedTimeout
}


// pollfrequency in millisecs
const POLL: u64 = 100;
// a block should arrive within this timeout in seconds
const BLOCK_TIMEOUT: u64 = 300;

impl FilterCalculator {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender, timeout: SharedTimeout) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut filtercalculator = FilterCalculator { network, chaindb, p2p, peer: None, peers: HashSet::new(), want: HashSet::new(), missing: Vec::new(), timeout };

        thread::spawn(move || { filtercalculator.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        let mut re_check = true;
        loop {
            self.timeout.lock().unwrap().check();
            // wait some time for incoming block messages, process them if available
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(POLL)) {
                match msg {
                    PeerMessage::Connected(pid) => {
                        if self.peer.is_none() {
                            debug!("block download from peer={}", pid);
                            self.peer = Some(pid);
                            re_check = true;
                        }
                        self.peers.insert(pid);
                    },
                    PeerMessage::Disconnected(pid) => {
                        self.peers.remove(&pid);
                        if self.peer.is_some() {
                            if self.peer.unwrap() == pid {
                                self.want.clear();
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
                                self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::Block);
                                thread::yield_now();
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
            if re_check  {
                self.download().expect("download failed");
                re_check = false;
            }

        }
    }

    fn download (&mut self) -> Result<(), MurmelError> {
        let genesis = genesis_block(self.network);
        // can not work if no peer is connected
        if let Some(peer) = self.peer {
            // if not already waiting for some blocks
            if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::Block) == false {
                let mut missing = self.missing.clone();
                if self.missing.is_empty() {
                    // compute the list of missing blocks
                    {
                        debug!("calculate missing blocks...");
                        let chaindb = self.chaindb.read().unwrap();
                        for header in chaindb.iter_trunk_rev(None) {
                            let id = header.bitcoin_hash();
                            if chaindb.may_have_block(&id)? == false {
                                missing.push(id);
                            }
                            else {
                                if chaindb.fetch_stored_block(&id)?.is_none () {
                                    missing.push(id);
                                }
                                else {
                                    break;
                                }
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
                }

                let mut cs = 0;
                if let Some(chunk) = missing.as_slice().chunks(self.p2p.back_pressure).next() {
                    cs = chunk.len();
                    let invs = chunk.iter().map(|s| { Inventory { inv_type: InvType::WitnessBlock, hash: s.clone() } }).collect::<Vec<_>>();
                    self.timeout.lock().unwrap().expect(peer, invs.len(), ExpectedReply::Block);
                    debug!("asking {} blocks from peer={}", invs.len(), peer);
                    self.p2p.send(P2PControl::Send(peer, NetworkMessage::GetData(invs)));
                    chunk.iter().for_each( |id| { self.want.insert(id.clone()); });
                }
                self.missing.clear();
                self.missing.extend(missing.iter().skip(cs));
            }
        }
        Ok(())
    }

    fn block(&mut self, peer: PeerId, block: &Block) -> Result<(), MurmelError> {
        if self.want.remove(&block.bitcoin_hash()) {
            let block_id = block.bitcoin_hash();
            let mut chaindb = self.chaindb.write().unwrap();
            // have to know header before storing a block
            if let Some(header) = chaindb.get_header(&block_id) {
                // do not store fake blocks
                if block.check_merkle_root() && block.check_witness_commitment() {
                    // cache output scripts for later calculation
                    chaindb.cache_scripts(block, header.height);
                    // if this is the next block for filter calculation
                    if let Some(prev_script) = chaindb.get_block_filter(&block.header.prev_blockhash, SCRIPT_FILTER) {
                        if let Some(prev_coin) = chaindb.get_block_filter(&block.header.prev_blockhash, COIN_FILTER) {
                            // store block
                            debug!("store block  {} {} peer={}", header.height, block_id, peer);
                            chaindb.store_block(block)?;
                            // calculate filters
                            let script_filter = BlockFilter::compute_script_filter(&block, chaindb.get_script_accessor(block))?;
                            let coin_filter = BlockFilter::compute_coin_filter(&block)?;
                            debug!("store filter {} {} size: {} {} peer={}", header.height, block_id, script_filter.content.len(), coin_filter.content.len(), peer);
                            // store known filters into header
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
            if self.want.is_empty () {
                chaindb.batch()?;
            }
        }
        else {
            debug!("received unwanted block {}", block.bitcoin_hash());
        }
        Ok(())
    }
}