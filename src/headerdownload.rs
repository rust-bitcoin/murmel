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
//! # Download headers
//!
use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::LoneBlockHeader,
    },
    network::{
        message::NetworkMessage,
        message_blockdata::{GetHeadersMessage, Inventory, InvType},
    },
    util::hash::Sha256dHash,
};
use connector::SharedLightningConnector;
use chaindb::SharedChainDB;
use error::MurmelError;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender, SERVICE_BLOCKS};
use std::{
    collections::VecDeque,
    sync::mpsc,
    thread,
    time::Duration,
};
use timeout::{ExpectedReply, SharedTimeout};

pub struct HeaderDownload {
    p2p: P2PControlSender,
    chaindb: SharedChainDB,
    timeout: SharedTimeout,
    lightning: SharedLightningConnector
}

impl HeaderDownload {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender, timeout: SharedTimeout, lightning: SharedLightningConnector) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut headerdownload = HeaderDownload { chaindb, p2p, timeout, lightning };

        thread::spawn(move || { headerdownload.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                if let Err(e) = match msg {
                    PeerMessage::Connected(pid) => {
                        if self.is_serving_blocks(pid) {
                            self.get_headers(pid)
                        } else {
                            Ok(())
                        }
                    }
                    PeerMessage::Disconnected(_) => {
                        Ok(())
                    }
                    PeerMessage::Message(pid, msg) => {
                        match msg {
                            NetworkMessage::Headers(ref headers) => if self.is_serving_blocks(pid) { self.headers(headers, pid) } else { Ok(()) },
                            NetworkMessage::Inv(ref inv) => if self.is_serving_blocks(pid) { self.inv(inv, pid) } else { Ok(()) },
                            NetworkMessage::Ping(_) => { Ok(()) }
                            _ => { Ok(()) }
                        }
                    }
                } {
                    error!("Error processing headers: {}", e);
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::Headers));
        }
    }

    fn is_serving_blocks(&self, peer: PeerId) -> bool {
        if let Some(peer_version) = self.p2p.peer_version(peer) {
            return peer_version.services & SERVICE_BLOCKS != 0;
        }
        false
    }

    // process an incoming inventory announcement
    fn inv(&mut self, v: &Vec<Inventory>, peer: PeerId) -> Result<(), MurmelError> {
        let mut ask_for_headers = false;
        for inventory in v {
            // only care for blocks
            if inventory.inv_type == InvType::Block {
                let chaindb = self.chaindb.read().unwrap();
                debug!("received inv for block {}", inventory.hash);
                if chaindb.get_header(&inventory.hash).is_none() {
                    // ask for header(s) if observing a new block
                    ask_for_headers = true;
                }
            } else {
                // do not spam us with transactions
                debug!("received unwanted inv {:?} peer={}", inventory.inv_type, peer);
                self.ban(peer, 10);
                return Ok(());
            }
        }
        if ask_for_headers {
            self.get_headers(peer)?;
        }
        Ok(())
    }

    /// get headers this peer is ahead of us
    fn get_headers(&mut self, peer: PeerId) -> Result<(), MurmelError> {
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::Headers) {
            return Ok(());
        }
        let chaindb = self.chaindb.read().unwrap();
        let locator = chaindb.header_locators();
        if locator.len() > 0 {
            let first = if locator.len() > 0 {
                *locator.first().unwrap()
            } else {
                Sha256dHash::default()
            };
            self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::Headers);
            self.send(peer, NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, first)));
        }
        Ok(())
    }

    fn headers(&mut self, headers: &Vec<LoneBlockHeader>, peer: PeerId) -> Result<(), MurmelError> {
        self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::Headers);

        if headers.len() > 0 {
            // current height
            let mut height;
            // some received headers were not yet known
            let mut some_new = false;
            let mut moved_tip = None;
            {
                let chaindb = self.chaindb.read().unwrap();

                if let Some(tip) = chaindb.header_tip() {
                    height = tip.height;
                } else {
                    return Err(MurmelError::NoTip);
                }
            }

            let mut headers_queue = VecDeque::new();
            headers_queue.extend(headers.iter());
            while !headers_queue.is_empty() {
                let mut disconnected_headers = Vec::new();
                {
                    let mut chaindb = self.chaindb.write().unwrap();
                    while let Some(header) = headers_queue.pop_front() {
                        // add to blockchain - this also checks proof of work
                        match chaindb.add_header(&header.header) {
                            Ok(Some((stored, unwinds, forwards))) => {
                                // POW is ok, stored top chaindb
                                some_new = true;

                                if let Some(forwards) = forwards {
                                    moved_tip = Some(forwards.last().unwrap().clone());
                                }
                                height = stored.height;

                                if let Some(unwinds) = unwinds {
                                    disconnected_headers.extend(unwinds.iter()
                                        .map(|h| chaindb.get_header(h).unwrap().header));
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(MurmelError::SpvBadProofOfWork) => {
                                info!("Incorrect POW, banning peer={}", peer);
                                self.ban(peer, 100);
                                return Ok(());
                            }
                            Err(e) => {
                                debug!("error {} processing header {} ", e, header.header.bitcoin_hash());
                                return Ok(());
                            }
                        }
                    }
                    chaindb.batch()?;
                }

                for header in &disconnected_headers {
                    self.lightning.lock().unwrap().block_disconnected(header);
                }
            }

            if some_new {
                // ask if peer knows even more
                self.get_headers(peer)?;
            }

            if let Some(new_tip) = moved_tip {
                info!("received {} headers new tip={} from peer={}", headers.len(), new_tip, peer);
                self.p2p.send(P2PControl::Height(height));
            } else {
                debug!("received {} known or orphan headers from peer={}", headers.len(), peer);
            }
        }
        Ok(())
    }

    fn ban(&self, peer: PeerId, score: u32) {
        self.p2p.send(P2PControl::Ban(peer, score))
    }

    fn send(&self, peer: PeerId, msg: NetworkMessage) {
        self.p2p.send(P2PControl::Send(peer, msg))
    }
}