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
        transaction::OutPoint,
        script::Script
    },
    network::{
        constants::Network,
        message::NetworkMessage,
        message_blockdata::{Inventory, InvType},
    }
};
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bip158::{BlockFilter, SCRIPT_FILTER, BlockFilterWriter};
use chaindb::SharedChainDB;
use error::MurmelError;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use std::{
    collections::HashSet,
    sync::mpsc,
    thread,
    time::Duration
};
use timeout::{ExpectedReply, SharedTimeout};

pub const TXID_FILTER:u8 = 'c' as u8;

pub struct FilterCalculator {
    network: Network,
    chaindb: SharedChainDB,
    p2p: P2PControlSender<NetworkMessage>,
    peer: Option<PeerId>,
    peers: HashSet<PeerId>,
    want: HashSet<Sha256dHash>,
    missing: Vec<Sha256dHash>,
    timeout: SharedTimeout<NetworkMessage>
}

impl FilterCalculator {
    pub fn new(network: Network, chaindb: SharedChainDB, p2p: P2PControlSender<NetworkMessage>, timeout: SharedTimeout<NetworkMessage>) -> PeerMessageSender<NetworkMessage> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut filtercalculator = FilterCalculator { network, chaindb, p2p, peer: None, peers: HashSet::new(), want: HashSet::new(), missing: Vec::new(), timeout };

        thread::Builder::new().name("filter calculator".to_string()).spawn(move || { filtercalculator.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        let mut re_check = true;
        loop {
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::Block));
            // wait some time for incoming block messages, process them if available
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                match msg {
                    PeerMessage::Connected(pid) => {
                        if self.peer.is_none() {
                            debug!("block download from peer={}", pid);
                            self.peer = Some(pid);
                            re_check = true;
                        }
                        self.peers.insert(pid);
                    },
                    PeerMessage::Disconnected(pid,_) => {
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
                        let chaindb = self.chaindb.read().unwrap();
                        debug!("calculate missing blocks...");
                        for header in chaindb.iter_trunk_rev(None) {
                            let id = header.bitcoin_hash();
                            if chaindb.may_have_block(&id)? == false {
                                missing.push(id);
                            }
                            else {
                                if let Some(block) = chaindb.fetch_stored_block(&id)? {
                                    if block.txids.is_empty() {
                                        missing.push(id);
                                    }
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
                        chaindb.store_block(&genesis)?;
                        let accessor = chaindb.get_script_accessor(&genesis);
                        let script_filter = BlockFilter::new_script_filter(&genesis, move |coin| accessor.resolve(coin))?;
                        chaindb.add_calculated_filter(&Sha256dHash::default(), &script_filter)?;
                        chaindb.add_calculated_filter(&Sha256dHash::default(), &Self::tx_filter(&genesis)?)?;
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
                    chaindb.cache_scripts(block, header.stored.height);
                    // if this is the next block for filter calculation
                    if let Some(prev_script) = chaindb.get_block_filter(&block.header.prev_blockhash, SCRIPT_FILTER) {
                        let script_filter;
                        {
                            let accessor = chaindb.get_script_accessor(&block);
                            script_filter = BlockFilter::new_script_filter(&block, |coin| accessor.resolve(coin))?;
                        }
                        chaindb.add_calculated_filter(&prev_script.filter_id(), &script_filter)?;
                    }
                    if let Some(prev_tx) = chaindb.get_block_filter(&block.header.prev_blockhash, TXID_FILTER) {
                        chaindb.add_calculated_filter(&prev_tx.filter_id(), &Self::tx_filter(block)?)?;
                    }
                    chaindb.store_block(block)?;
                    self.p2p.send(P2PControl::Broadcast(NetworkMessage::Inv(vec!(Inventory{inv_type: InvType::Block, hash:block_id}))));
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

    fn tx_filter(block: &Block) -> Result<BlockFilter, MurmelError> {
        let mut content = Vec::new();
        let mut writer = BlockFilterWriter::new(&mut content, block);
        for tx in &block.txdata {
            writer.add_element(&tx.bitcoin_hash()[..])
        }
        writer.finish()?;
        Ok(BlockFilter::new(block.bitcoin_hash(), TXID_FILTER, content.as_slice()))
    }
}