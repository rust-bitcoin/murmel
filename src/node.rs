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
//! # Bitcoin SPV node
//!
//! Implements a node that reacts to network messages and serves higher application
//! layer with a fresh view of the Bitcoin blockchain.
//!


use connector::LightningConnector;
use configdb::ConfigDB;
use chaindb::ChainDB;
use error::SPVError;
use p2p::{PeerId, PeerMap};

use lightning::chain::chaininterface::BroadcasterInterface;

use bitcoin::{
    BitcoinHash,
    blockdata::{
        block::{Block, LoneBlockHeader},
        transaction::Transaction,
    },
    util::hash::Sha256dHash,
    network::{
        address::Address,
        constants::Network,
        message::{
            NetworkMessage
        },
        message_blockdata::*
    }
};

use std::{
    sync::{Mutex, RwLock, Arc},
    time::{SystemTime, UNIX_EPOCH},
    collections::VecDeque
};

/// The node replies with this process result to messages
#[derive(Clone, Eq, PartialEq)]
pub enum ProcessResult {
    /// Acknowledgment
    Ack,
    /// Acknowledgment, P2P should indicate the new height in future version messages
    Height(u32),
    /// message ignored
    Ignored,
    /// increase ban score
    Ban(u32),
}


/// a helper class to implement LightningConnector
pub struct Broadcaster {
    // the peer map shared with node and P2P
    peers: Arc<RwLock<PeerMap>>
}

impl BroadcasterInterface for Broadcaster {
    /// send a transaction to all connected peers
    fn broadcast_transaction(&self, tx: &Transaction) {
        let txid = tx.txid();
        for (pid, peer) in self.peers.read().unwrap().iter() {
            debug!("send tx {} peer={}", txid, pid);
            peer.lock().unwrap().send(&NetworkMessage::Tx(tx.clone())).unwrap_or(());
        }
    }
}

/// The local node processing incoming messages
pub struct Node {
    // peer map shared with P2P and the LightningConnector's broadcaster
    peers: Arc<RwLock<PeerMap>>,
    // type of the connected network
    network: Network,
    // the configuration db
    db: Arc<Mutex<ConfigDB>>,
    // the blockchain db
    chaindb: RwLock<ChainDB>,
    // connector serving Layer 2 network
    connector: Arc<LightningConnector>,
    // download queue
    download_queue: Mutex<VecDeque<Sha256dHash>>
}

impl Node {
    /// Create a new local node
    pub fn new(network: Network, db: Arc<Mutex<ConfigDB>>, chaindb: ChainDB, peers: Arc<RwLock<PeerMap>>) -> Node {
        let connector = LightningConnector::new(network,Arc::new(Broadcaster { peers: peers.clone() }));
        Node {
                peers,
                network,
                db,
                chaindb: RwLock::new(chaindb),
                connector: Arc::new(connector),
                download_queue: Mutex::new(VecDeque::new()) }
    }

    /// initialize node
    pub fn init(&self) -> Result<(), SPVError> {
        self.chaindb.write().unwrap().init()?;
        Ok(())
    }

    /// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pid: PeerId) -> Result<ProcessResult, SPVError> {
        self.get_headers(pid)?;

        Ok(ProcessResult::Ack)
    }

    fn download_blocks(&self, pid: PeerId, blocks: Vec<Sha256dHash>) -> Result<bool, SPVError> {
        /*
        let mut dq = self.download_queue.lock().expect("download queue poisoned");

        if let Some(new_blocks) = blocks.iter ().position(|b| !dq.iter().any(|a| { a == b })) {
            dq.extend(blocks[new_blocks ..].iter());
        }

        if let Some (ask) = dq.front() {
            let inventory = vec!({ Inventory { inv_type: InvType::WitnessBlock, hash: ask.clone() } });
            self.send(pid, &NetworkMessage::GetData(inventory))?;
            return Ok(true);
        }
        */
        Ok(false)
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, _pid: PeerId) -> Result<ProcessResult, SPVError> {
        Ok(ProcessResult::Ack)
    }

    /// Process incoming messages
    pub fn process(&self, msg: &NetworkMessage, peer: PeerId) -> Result<ProcessResult, SPVError> {
        match msg {
            &NetworkMessage::Ping(nonce) => self.ping(nonce, peer),
            &NetworkMessage::Headers(ref v) => self.headers(v, peer),
            &NetworkMessage::Block(ref b) => self.block(b, peer),
            &NetworkMessage::Inv(ref v) => self.inv(v, peer),
            &NetworkMessage::Addr(ref v) => self.addr(v, peer),
            _ => Ok(ProcessResult::Ban(1))
        }
    }

    // received ping
    fn ping(&self, nonce: u64, peer: PeerId) -> Result<ProcessResult, SPVError> {
        // send pong
        self.send(peer, &NetworkMessage::Pong(nonce))
    }

    // process headers message
    fn headers(&self, headers: &Vec<LoneBlockHeader>, peer: PeerId) -> Result<ProcessResult, SPVError> {
        if headers.len() > 0 {
            let mut download = Vec::new();
            // current height
            let mut height;
            // some received headers were not yet known
            let mut some_new = false;
            let mut moved_tip = None;
            {
                let chaindb = self.chaindb.read().unwrap();

                if let Some(tip) = chaindb.tip() {
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
                                    download.extend(forwards.iter());
                                }
                                height = stored.height;

                                if let Some(unwinds) = unwinds {
                                    for h in &unwinds {
                                        if chaindb.unwind_tip(h)? {
                                            debug!("unwind {}", h);
                                        }
                                    }
                                    disconnected_headers.extend(unwinds.iter()
                                        .map(|h| chaindb.get_header(h).unwrap().header));
                                    break;
                                }
                            }
                            Ok(None) => {},
                            Err(SPVError::SpvBadProofOfWork) => {
                                info!("Incorrect POW, banning peer={}", peer);
                                return Ok(ProcessResult::Ban(100));
                            }
                            Err(e) => {
                                debug!("error {} on {} ", e, header.header.bitcoin_hash());
                                return Ok(ProcessResult::Ignored)
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
                // ask if peer knows even more
                self.get_headers(peer)?;
            }

            if let Some(new_tip) = moved_tip {
                info!("received {} headers new tip={} from peer={}", headers.len(), new_tip, peer);
                self.download_blocks(peer, download)?;
                return Ok(ProcessResult::Height(height));
            } else {
                debug!("received {} known or orphan headers from peer={}", headers.len(), peer);
                return Ok(ProcessResult::Ack);
            }
        } else {
            Ok(ProcessResult::Ignored)
        }
    }

    // process an incoming block
    fn block(&self, block: &Block, peer: PeerId) -> Result<ProcessResult, SPVError> {
        {
            debug!("store block {}", block.bitcoin_hash());
            let mut chaindb = self.chaindb.write().unwrap();
            chaindb.extend_blocks_utxo_filters(block)?;
            {
                let mut dq = self.download_queue.lock().unwrap();
                if let Some(expected) = dq.pop_front() {
                    if expected != block.bitcoin_hash() {
                        dq.push_front(expected);
                    }
                }
            }
        }
        self.get_headers(peer)?;
        Ok(ProcessResult::Ack)
    }

    // process an incoming inventory announcement
    fn inv(&self, v: &Vec<Inventory>, peer: PeerId) -> Result<ProcessResult, SPVError> {
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
                return Ok(ProcessResult::Ban(10));
            }
        }
        if ask_for_headers {
            self.get_headers(peer)?;
            return Ok(ProcessResult::Ack);
        }
        else {
            return Ok(ProcessResult::Ignored);
        }
    }

    // process incoming addr messages
    fn addr(&self, v: &Vec<(u32, Address)>, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let mut result = ProcessResult::Ignored;
        // store if interesting, that is ...
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut db = self.db.lock().unwrap();
        let mut tx = db.transaction()?;
        for a in v.iter() {
            // if not tor
            if a.1.socket_addr().is_ok() {
                // if segwit full node and not older than 3 hours
                if a.1.services & 9 == 9 && a.0 > now - 3 * 60 * 30 {
                    tx.store_peer(&a.1, a.0, 0)?;
                    result = ProcessResult::Ack;
                    info!("stored address {:?} peer={}", a.1.socket_addr()?, peer);
                }
            }
        }
        tx.commit()?;
        Ok(result)
    }

    fn next_block(&self) -> Option<Sha256dHash> {
        let dq = self.download_queue.lock().expect("download queue posined");
        if let Some(f) = dq.front() {
            return Some(f.clone());
        }
        None
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: PeerId) -> Result<ProcessResult, SPVError> {
        if !self.download_blocks(peer, vec!())? {
            let chaindb = self.chaindb.read().unwrap();
            let locator = chaindb.header_locators();
            if locator.len() > 0 {
                let first = if locator.len() > 0 {
                    *locator.first().unwrap()
                } else {
                    Sha256dHash::default()
                };
                return self.send(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, first)));
            }
        }
        Ok(ProcessResult::Ack)
    }

    /// send to peer
    fn send(&self, peer: PeerId, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        if let Some(sender) = self.peers.read().unwrap().get(&peer) {
            sender.lock().unwrap().send(msg)?;
        }
        Ok(ProcessResult::Ack)
    }

    /// send the same message to all connected peers
    #[allow(dead_code)]
    fn broadcast(&self, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        for (_, sender) in self.peers.read().unwrap().iter() {
            sender.lock().unwrap().send(msg)?;
        }
        Ok(ProcessResult::Ack)
    }
    /// send a transaction to all connected peers
    #[allow(dead_code)]
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<ProcessResult, SPVError> {
        self.broadcast(&NetworkMessage::Tx(tx.clone()))
    }

    /// retrieve the interface a higher application layer e.g. lightning may use to send transactions to the network
    #[allow(dead_code)]
    pub fn get_broadcaster(&self) -> Arc<Broadcaster> {
        self.connector.get_broadcaster()
    }
}
