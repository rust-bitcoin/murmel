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
//! # Serve general header and block requests
//!

use bitcoin::{
    BitcoinHash,
    blockdata::block::{Block, LoneBlockHeader},
    consensus::encode::VarInt,
    network::message::NetworkMessage,
    network::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory, InvType}
};
use chaindb::SharedChainDB;
use error::MurmelError;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use std::{
    sync::mpsc,
    thread
};

pub struct BlockServer {
    p2p: P2PControlSender,
    chaindb: SharedChainDB,
}

impl BlockServer {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut block_server = BlockServer { chaindb, p2p };

        thread::spawn(move || { block_server.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        while let Ok(msg) = receiver.recv() {
            if let Err(e) = match msg {
                PeerMessage::Message(pid, msg) => {
                    match msg {
                        NetworkMessage::GetHeaders(get) => self.get_headers(pid, get),
                        NetworkMessage::GetBlocks(get) => self.get_blocks(pid, get),
                        NetworkMessage::GetData(get) => self.get_data(pid, get),
                        _ => { Ok(()) }
                    }
                }
                _ => {Ok(())}
            } {
                error!("Error processing headers: {}", e);
            }
        }
        panic!("Block server thread failed.");
    }

    fn get_headers(&self, peer: PeerId, get: GetHeadersMessage) -> Result<(), MurmelError> {
        let chaindb = self.chaindb.read().unwrap();
        for locator in get.locator_hashes.iter () {
            if let Some(pos) = chaindb.pos_on_trunk(locator) {
                let mut headers = Vec::with_capacity(2000);
                for header in chaindb.iter_trunk(pos).take(2000) {
                    headers.push(LoneBlockHeader{header: header.header, tx_count: VarInt(0)})
                }
                self.p2p.send(P2PControl::Send(peer, NetworkMessage::Headers(headers)));
                break;
            }
        }
        Ok(())
    }

    fn get_blocks(&self, peer: PeerId, get: GetBlocksMessage) -> Result<(), MurmelError> {
        let chaindb = self.chaindb.read().unwrap();
        for locator in get.locator_hashes.iter () {
            if let Some(pos) = chaindb.pos_on_trunk(locator) {
                for header in chaindb.iter_trunk(pos).take(500) {
                    if let Some(txdata) = chaindb.fetch_txdata(&header.header.bitcoin_hash())? {
                        self.p2p.send(P2PControl::Send(peer, NetworkMessage::Block(Block{header: header.header, txdata})));
                    }
                }
                break;
            }
        }
        Ok(())
    }

    fn get_data(&self, peer: PeerId, get: Vec<Inventory>) -> Result<(), MurmelError> {
        let chaindb = self.chaindb.read().unwrap();
        for inv in get {
            if inv.inv_type == InvType::WitnessBlock {
                if let Some(header) = chaindb.get_header(&inv.hash) {
                    if let Some(txdata) = chaindb.fetch_txdata(&header.header.bitcoin_hash())? {
                        self.p2p.send(P2PControl::Send(peer, NetworkMessage::Block(Block{header: header.header, txdata})));
                    }
                }
            }
        }
        Ok(())
    }
}