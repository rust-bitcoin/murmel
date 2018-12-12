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


use bitcoin::blockdata::block::{Block, LoneBlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::address::Address;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::*;
use bitcoin::network::constants::Network;
use bitcoin::util::hash::{BitcoinHash, Sha256dHash};
use connector::LightningConnector;
use database::DB;
use error::SPVError;
use futures::task::Context;
use lightning::chain::chaininterface::BroadcasterInterface;
use p2p::{P2P, PeerId, PeerMap};
use std::sync::{Mutex, RwLock};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The node replies with this process result to messages
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
#[derive(Clone)]
pub struct Node {
    // all data in inner to simplify passing them into closures
    inner: Arc<Inner>
}

struct Inner {
    // the connected P2P network
    p2p: Arc<P2P>,
    // peer map shared with P2P and the LightningConnector's broadcaster
    peers: Arc<RwLock<PeerMap>>,
    // type of the connected network
    network: Network,
    // the persistent blockchain storing previously downloaded header and blocks
    db: Arc<Mutex<DB>>,
    // connector serving Layer 2 network
    connector: Arc<LightningConnector>,
    // header chain with most work
}

impl Node {
    /// Create a new local node
    pub fn new(p2p: Arc<P2P>, network: Network, db: Arc<Mutex<DB>>, _server: bool, peers: Arc<RwLock<PeerMap>>) -> Node {
        let connector = LightningConnector::new(network,Arc::new(Broadcaster { peers: peers.clone() }));
        Node {
            inner: Arc::new(Inner {
                p2p,
                peers,
                network,
                db,
                connector: Arc::new(connector)
            })
        }
    }

    /// Initialize node before P2P communication starts
    pub fn init_before_p2p(&self, _ctx: &mut Context) {
        trace!("initialize node before P2P")
    }

    /// Load headers from database
    pub fn load_headers(&self) -> Result<(), SPVError> {
        info!("loading headers from database...");
        let mut db = self.inner.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.init_node(self.inner.network)?;
        tx.commit()?;
        Ok(())
    }

    /// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pid: PeerId, _ctx: &mut Context) -> Result<ProcessResult, SPVError> {
        self.get_headers(pid)?;

        Ok(ProcessResult::Ack)
    }

    // decide if the block was fully processed
    fn is_processed (&self, _block: &Sha256dHash) -> bool {
        false
    }

    fn download_blocks(&self, pid: PeerId, blocks: Vec<Sha256dHash>) -> Result<ProcessResult, SPVError> {
        // TODO decide if we need it (BIP158)
        let inventory = blocks.iter().map(|b| {Inventory{inv_type: InvType::WitnessBlock, hash: b.clone()}}).collect();
        self.send(pid, &NetworkMessage::GetData(inventory))?;
        Ok(ProcessResult::Ack)
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, _pid: PeerId) -> Result<ProcessResult, SPVError> {
        Ok(ProcessResult::Ack)
    }

    /// Process incoming messages
    pub fn process(&self, msg: &NetworkMessage, peer: PeerId, _: &mut Context) -> Result<ProcessResult, SPVError> {
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
            // headers to unwind due to re-org
            let mut disconnected_headers = Vec::new();
            // current height
            let height;
            // some received headers were not yet known
            let mut some_new = false;
            let mut tip_moved = false;
            {
                // new scope to limit lock
                let mut db = self.inner.db.lock().unwrap();
                let tx = db.transaction()?;

                for header in headers {
                    if let Some(mut old_tip) = tx.get_tip()? {
                        // add to in-memory blockchain - this also checks proof of work
                        match tx.insert_header(&header.header) {
                            Ok(_) => {
                                if let Some(new_tip) = tx.get_tip()? {
                                    tip_moved = tip_moved || new_tip != old_tip;
                                    let header_hash = header.header.bitcoin_hash();
                                    some_new = true;

                                    if header_hash == new_tip && header.header.prev_blockhash != old_tip {
                                        // this is a re-org. Compute headers to unwind
                                        while !tx.is_on_trunk(&old_tip) {
                                            if let Some(old_header) = tx.get_header(&old_tip) {
                                                old_tip = old_header.header.prev_blockhash;
                                                disconnected_headers.push(old_header.header);
                                            }
                                        }
                                    }
                                }
                            }
                            Err(SPVError::SpvBadProofOfWork) => {
                                info!("Incorrect POW, banning peer={}", peer);
                                return Ok(ProcessResult::Ban(100));
                            }
                            Err(_) => return Ok(ProcessResult::Ignored)
                        }
                    }
                }
                if let Some(ref new_tip) = tx.get_tip()? {
                    if let Some(header) = tx.get_header(new_tip) {
                        height = header.height;
                    }
                    else {
                        return Err(SPVError::Generic("no tip header stored".to_string()));
                    }
                }
                else {
                    return Err(SPVError::Generic("no tip".to_string()));
                }
                if tip_moved {
                    if let Some(new_tip) = tx.get_tip()? {
                        info!("received {} headers new tip={} from peer={}", headers.len(), new_tip, peer);
                    }
                    tx.commit()?;
                } else {
                    tx.commit()?;
                    debug!("received {} known or orphan headers from peer={}", headers.len(), peer);
                    return Ok(ProcessResult::Ban(5));
                }
            }

            // notify lightning connector of disconnected blocks
            for header in disconnected_headers {
                // limit context
                self.inner.connector.block_disconnected(&header);
            }
            if some_new {
                // ask if peer knows even more
                self.get_headers(peer)?;
            }

            if tip_moved {
                Ok(ProcessResult::Height(height))
            } else {
                Ok(ProcessResult::Ack)
            }
        } else {
            Ok(ProcessResult::Ignored)
        }
    }

    // process an incoming block
    fn block(&self, block: &Block, _peer: PeerId) -> Result<ProcessResult, SPVError> {
        let mut db = self.inner.db.lock().unwrap();
        let tx = db.transaction()?;
        // header should be known already, otherwise it might be spam
        if let Some(_block_node) = tx.get_header(&block.bitcoin_hash()) {
            debug!("store block {}", block.bitcoin_hash());
            tx.store_block(block)?;
            debug!("store block {} done", block.bitcoin_hash());
            return Ok(ProcessResult::Ack);
        }
        Ok(ProcessResult::Ignored)
    }

    // process an incoming inventory announcement
    fn inv(&self, v: &Vec<Inventory>, peer: PeerId) -> Result<ProcessResult, SPVError> {
        for inventory in v {
            // only care of blocks
            if inventory.inv_type == InvType::Block {
                let mut db = self.inner.db.lock().unwrap();
                let tx = db.transaction()?;
                if tx.get_header(&inventory.hash).is_none() {
                    // ask for header(s) if observing a new block
                    self.get_headers(peer)?;
                    return Ok(ProcessResult::Ack);
                }
            } else {
                // do not spam us with transactions
                debug!("received unwanted inv {:?} peer={}", inventory.inv_type, peer);
                return Ok(ProcessResult::Ban(10));
            }
        }
        Ok(ProcessResult::Ignored)
    }

    // process incoming addr messages
    fn addr(&self, v: &Vec<(u32, Address)>, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let mut result = ProcessResult::Ignored;
        // store if interesting, that is ...
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut db = self.inner.db.lock().unwrap();
        let tx = db.transaction()?;
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

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let mut db = self.inner.db.lock().unwrap();
        let tx = db.transaction()?;
        let locator = tx.locator_hashes();
        if locator.len() > 0 {
            debug!("locator {} {}", locator[0], locator.len());
            let last = if locator.len() > 0 {
                *locator.last().unwrap()
            } else {
                Sha256dHash::default()
            };
            return self.send(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)));
        }
        else {
            debug!("empty locator");
        }
        Ok(ProcessResult::Ack)
    }

    /// send to peer
    fn send(&self, peer: PeerId, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        if let Some(sender) = self.inner.peers.read().unwrap().get(&peer) {
            sender.lock().unwrap().send(msg)?;
        }
        Ok(ProcessResult::Ack)
    }

    /// send the same message to all connected peers
    #[allow(dead_code)]
    fn broadcast(&self, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        for (_, sender) in self.inner.peers.read().unwrap().iter() {
            sender.lock().unwrap().send(msg)?;
        }
        Ok(ProcessResult::Ack)
    }
    /// send a transaction to all connected peers
    #[allow(dead_code)]
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<ProcessResult, SPVError> {
        self.broadcast(&NetworkMessage::Tx(tx.clone()))
    }

    /// retrieve the interface for lighning network
    pub fn get_chain_watch_interface(&self) -> Arc<LightningConnector> {
        self.inner.connector.clone()
    }

    /// retrieve the interface a higher application layer e.g. lighning may use to send transactions to the network
    #[allow(dead_code)]
    pub fn get_broadcaster(&self) -> Arc<Broadcaster> {
        self.inner.connector.get_broadcaster()
    }
}

#[inline]
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}