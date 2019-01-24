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
//! # Messsage dispatcher
//!


use connector::LightningConnector;
use configdb::SharedConfigDB;
use chaindb::SharedChainDB;
use error::SPVError;
use p2p::{PeerId, PeerMessageSender, PeerMessageReceiver, P2PControlSender, P2PControl, PeerMessage};
use filtercalculator::FilterCalculator;

use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::{Block, LoneBlockHeader}
    },
    util::hash::Sha256dHash,
    network::{
        address::Address,
        constants::Network,
        message::NetworkMessage,
        message_blockdata::*,
    },
};

use std::{
    thread,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
    collections::VecDeque,
};


/// The local node processing incoming messages
pub struct Dispatcher {
    p2p: P2PControlSender,
    // the configuration db
    configdb: SharedConfigDB,
    // the blockchain db
    chaindb: SharedChainDB,
    // block downloader sender
    filter_calculator: PeerMessageSender,
    // lightning connector
    connector: Arc<LightningConnector>
}

impl Dispatcher {
    /// Create a new local node
    pub fn new(network: Network, configdb: SharedConfigDB, chaindb: SharedChainDB, server: bool, connector: Arc<LightningConnector>, p2p: P2PControlSender, incoming: PeerMessageReceiver) -> Arc<Dispatcher> {


        let block_downloader = if server {
            FilterCalculator::new(network, chaindb.clone(), p2p.clone())
        }
        else {
            PeerMessageSender::dummy()
        };

        let dispatcher = Arc::new(Dispatcher {
            p2p,
            configdb,
            chaindb,
            filter_calculator: block_downloader,
            connector
        });

        let d2 = dispatcher.clone();
        thread::spawn(move || { d2.incoming_messages_loop (incoming) });

        dispatcher
    }

    fn incoming_messages_loop (&self, incoming: PeerMessageReceiver) {
        while let Ok(pm) = incoming.recv() {
            match pm {
                PeerMessage::Message(pid, msg) => {
                    if let Err(e) = self.process(msg, pid) {
                        debug!("error processing a message {} peer={}", e, pid);
                    }
                },
                PeerMessage::Connected(pid) => {
                    if let Err(e) = self.connected(pm) {
                        debug!("error at connect {} peer={}", e, pid);
                    }
                },
                PeerMessage::Disconnected(pid) => {
                    if let Err(e) = self.disconnected(pm) {
                        debug!("error at disconnect {} peer={}", e, pid);
                    }
                }
            }
        }
        panic!("dispatcher failed");
    }

    /// initialize node
    pub fn init(&self) -> Result<(), SPVError> {
        self.chaindb.write().unwrap().init()?;
        Ok(())
    }

    /// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pm: PeerMessage) -> Result<(), SPVError> {
        debug!("connected peer={}", pm.peer_id());
        self.get_headers(pm.peer_id())?;
        self.filter_calculator.send(pm);
        Ok(())
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, pm: PeerMessage) -> Result<(), SPVError> {
        self.filter_calculator.send(pm);
        Ok(())
    }

    /// Process incoming messages
    pub fn process(&self, msg: NetworkMessage, peer: PeerId) -> Result<(), SPVError> {
        Ok(match msg {
            NetworkMessage::Ping(nonce) => { self.ping(nonce, peer); Ok(()) },
            NetworkMessage::Headers(ref v) => self.headers(v, peer),
            NetworkMessage::Block(b) => self.block(b, peer),
            NetworkMessage::Inv(v) => self.inv(v, peer),
            NetworkMessage::Addr(ref v) => self.addr(v, peer),
            _ => { self.ban(peer,1); Ok(()) }
        }?)
    }

    // received ping
    fn ping(&self, nonce: u64, peer: PeerId) {
        // send pong
        self.send(peer, NetworkMessage::Pong(nonce))
    }

    // process headers message
    fn headers(&self, headers: &Vec<LoneBlockHeader>, peer: PeerId) -> Result<(), SPVError> {
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
                    return Err(SPVError::NoTip);
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
                            Err(SPVError::SpvBadProofOfWork) => {
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

                // notify lightning connector of disconnected blocks
                for header in &disconnected_headers {
                    // limit context
                    self.connector.block_disconnected(header);
                }
            }

            if some_new {
                // ping calculator, so it re-checks work
                self.filter_calculator.send_network(peer, NetworkMessage::Ping(0));
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

    // process an incoming block
    fn block(&self, block: Block, peer: PeerId) -> Result<(), SPVError> {
        self.filter_calculator.send_network(peer, NetworkMessage::Block(block));
        Ok(())
    }

    // process an incoming inventory announcement
    fn inv(&self, v: Vec<Inventory>, peer: PeerId) -> Result<(), SPVError> {
        let mut ask_for_headers = false;
        for inventory in &v {
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
                return Ok(())
            }
        }
        if ask_for_headers {
            self.get_headers(peer)?;
        }
        self.filter_calculator.send_network(peer, NetworkMessage::Inv(v));
        Ok(())
    }

    // process incoming addr messages
    fn addr(&self, v: &Vec<(u32, Address)>, peer: PeerId) -> Result<(), SPVError> {
        // store if interesting, that is ...
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut db = self.configdb.lock().unwrap();
        let mut tx = db.transaction()?;
        for a in v.iter() {
            // if not tor
            if a.1.socket_addr().is_ok() {
                // if segwit full node and not older than 3 hours
                if a.1.services & 9 == 9 && a.0 > now - 3 * 60 * 30 {
                    tx.store_peer(&a.1, a.0, 0)?;
                    debug!("stored address {:?} peer={}", a.1.socket_addr()?, peer);
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: PeerId) -> Result<(), SPVError> {
        let chaindb = self.chaindb.read().unwrap();
        let locator = chaindb.header_locators();
        if locator.len() > 0 {
            let first = if locator.len() > 0 {
                *locator.first().unwrap()
            } else {
                Sha256dHash::default()
            };
            self.send(peer,NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, first)));
        }
        Ok(())
    }

    fn ban (&self, peer: PeerId, score: u32) {
        self.p2p.send(P2PControl::Ban(peer, score))
    }

    /// send to peer
    fn send(&self, peer: PeerId, msg: NetworkMessage) {
        self.p2p.send(P2PControl::Send(peer, msg))
    }
}
