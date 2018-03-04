//Copyright 2018 Tamas Blummer
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

use bitcoin::blockdata::blockchain::Blockchain;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::constants::{magic, Network};
use bitcoin::network::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::network::message_blockdata::*;
use bitcoin::network::message_network::*;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use database::DB;
use dispatcher::Tx;
use error::SPVError;
use rand::{Rng, StdRng};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::Arc;

lazy_static! {
    static ref STDRNG : Mutex<StdRng> = Mutex::new(StdRng::new().unwrap());
}

use connector::LightningConnector;

/// a connected peer
pub struct Peer {
    pub tx: Tx,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub version: VersionMessage,
    pub banscore: AtomicUsize,
}

/// The local node processing incoming messages
pub struct Node {
    pub network: Network,
    pub height: AtomicUsize,
    pub nonce: u64,
    pub peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    pub blockchain: Mutex<Blockchain>,
    pub db: Mutex<DB>,
    pub connector: LightningConnector
}


impl Node {
    /// Create a new local node for a network that uses the given database
    pub fn new(network: Network, db: DB) -> Node {
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let connector = LightningConnector::new(
            Broadcaster::new(peers.clone(), magic(network)));
        Node {
            network,
            height: AtomicUsize::new(0),
            nonce: STDRNG.lock().unwrap().next_u64(),
            peers,
            blockchain: Mutex::new(Blockchain::new(network)),
            db : Mutex::new(db),
            connector
        }
    }

    /// Load headers from database
    pub fn load_headers(&self) -> Result<(), SPVError> {
        info!("loading headers from database...");
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if let Ok(tip) = tx.get_tip() {
            let mut n = 0;
            let mut blockchain = self.blockchain.lock().unwrap();
            for header in tx.get_headers (&genesis_block(self.network).bitcoin_hash(), &tip)? {
                if blockchain.add_header(header).is_ok() {
                    n += 1;
                }
            }
            self.height.store(blockchain.best_tip_height() as usize, Ordering::Relaxed);
            info!("loaded {} headers from database", n);
        }
        else {
            info!("no headers in the database");
        }
        tx.rollback()?;
        Ok(())
    }

    /// Process incoming messages
    pub fn process(&self, msg: &RawNetworkMessage, peer: &Peer) -> Result<(), SPVError> {
        match msg.payload {
            // reply top ping with pong
            NetworkMessage::Ping(nonce) => {
                self.reply(peer, &NetworkMessage::Pong(nonce))
            }
            // store headers received
            NetworkMessage::Headers(ref v) => {
                if v.len() > 0 {
                    // blocks we want to download
                    let mut ask_for_blocks = Vec::new();
                    let mut disconnected_headers = Vec::new();

                    {
                        // new scope to limit lock

                        // always lock blockchain before db to avoid deadlock (if need to lock both)
                        let mut blockchain = self.blockchain.lock().unwrap();

                        let mut db = self.db.lock().unwrap();
                        let tx = db.transaction()?;

                        for header in v {
                            let old_tip = blockchain.best_tip_hash();
                            // add to in-memory blockchain - this also checks proof of work
                            if blockchain.add_header(header.header).is_ok() {

                                let new_tip = blockchain.best_tip_hash ();
                                let header_hash = header.header.bitcoin_hash();
                                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
                                if header.header.time > now - 60*60*24 && new_tip ==  header_hash {
                                    // if not older than a day and extending the trunk then ask for the block
                                    ask_for_blocks.push (new_tip);
                                }

                                tx.insert_header(&header.header)?;

                                if header_hash == new_tip && header.header.prev_blockhash != old_tip {
                                    let mut prevhash = header.header.prev_blockhash;
                                    // a re-organisation happened
                                    while !blockchain.get_block(prevhash).unwrap().is_on_main_chain(&blockchain) {
                                        let previous = blockchain.get_block(prevhash).unwrap();
                                        disconnected_headers.push(previous.block.header);
                                        prevhash = previous.block.header.prev_blockhash;
                                    }
                                }
                            }
                        }
                        tx.set_tip(&blockchain.best_tip_hash())?;

                        tx.commit()?;
                        info!("add {} headers tip={} from peer={}", v.len(),
                              blockchain.best_tip_hash(), peer.remote_addr);
                    }

                    disconnected_headers.reverse();
                    for header in disconnected_headers {
                        self.connector.block_disconnected(&header);
                    }
                    // ask for new blocks on trunk
                    self.get_blocks(peer, ask_for_blocks)?;
                    // ask if peer knows even more
                    self.get_headers(peer)
                } else {
                    Ok(())
                }
            }
            NetworkMessage::Block(ref b) => {
                let mut blockchain = self.blockchain.lock().unwrap();
                // header should be known already, otherwise it might be spam
                let block = blockchain.get_block(b.bitcoin_hash());
                if block.is_some() {
                    let block = block.unwrap();
                    if block.block.txdata.is_empty() {
                        if blockchain.get_block(b.bitcoin_hash()).unwrap().is_on_main_chain(&blockchain) {

                            // limit context
                            {
                                // store a block if it is on the chain with most work
                                let mut db = self.db.lock().unwrap();
                                let tx = db.transaction()?;
                                tx.insert_block(&b)?;
                                tx.commit()?;
                            }

                            // send new block to lighning connector
                            self.connector.block_connected(&b, block.height);
                        }
                    }
                }
                Ok(())
            }
            NetworkMessage::Inv(ref v) => {
                for inventory in v {
                    if inventory.inv_type == InvType::Block
                        && self.blockchain.lock().unwrap().get_block(inventory.hash).is_none() {
                        // ask for header(s) if observing a new block
                        self.get_headers(peer)?;
                        break;
                    }
                }
                Ok(())
            }
            _ => {
                trace!("ignored {} message from peer={}", msg.command(), peer.remote_addr);
                Ok(())
            }
        }
    }

    /// get the blocks we are interested in
    pub fn get_blocks(&self, peer: &Peer, blocks: Vec<Sha256dHash>) -> Result<(), SPVError> {
        let mut invs = Vec::new();
        for b in blocks {
            invs.push(Inventory{
                inv_type: InvType::Block,
                hash: b
            });
        }
        self.reply(peer, &NetworkMessage::GetData(invs))
    }

    /// get headers this peer is ahead of us
    pub fn get_headers(&self, peer: &Peer) -> Result<(), SPVError> {
        let locator = self.blockchain.lock().unwrap().locator_hashes();
        let last = if locator.len() > 0 {
            *locator.last().unwrap()
        } else {
            Sha256dHash::default()
        };
        self.reply(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)))
    }

    /// Reply to peer
    fn reply(&self, peer: &Peer, msg: &NetworkMessage) -> Result<(), SPVError> {
        let raw = self.raw_message(msg);
        trace!("sending {} message to peer={}", raw.command(), peer.remote_addr);
        if peer.tx.unbounded_send(raw).is_err() {
            Err(SPVError::Generic(format!("can not speak to peer={}", peer.remote_addr)))
        } else {
            Ok(())
        }
    }

    /// send a new transaction to all peers
    pub fn send_transaction (&self, tx : Transaction) -> Result <(), SPVError> {
        self.broadcast (&NetworkMessage::Tx(tx))
    }

    /// send the same message to all connected peers
    pub fn broadcast (&self, msg: &NetworkMessage) -> Result <(), SPVError> {
        for (_, peer) in self.peers.lock().unwrap().iter() {
            self.reply(peer, msg)?;
        }
        Ok(())
    }

    /// wrap a message into an envelope with magic number and checksum
    pub fn raw_message(&self, payload: &NetworkMessage) -> RawNetworkMessage {
        RawNetworkMessage { magic: magic(self.network), payload: payload.clone() }
    }

    /// increment ban score for a misbehaving peer. Ban if score reaches 100
    pub fn ban(peer: &Peer, addscore: u16) -> Result<(), io::Error> {
        let oldscore = peer.banscore.fetch_add(addscore as usize, Ordering::Relaxed);
        if oldscore + addscore as usize >= 100 {
            info!("banned peer={}", peer.remote_addr);
            Err(io::Error::new(io::ErrorKind::Other, format!("banned peer={}", peer.remote_addr)))
        } else {
            Ok(())
        }
    }
}

/// a helper class to implement LightningConnector
pub struct Broadcaster {
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    magic: u32
}

impl Broadcaster {
    pub fn new (peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>, magic: u32) -> Broadcaster {
        Broadcaster { peers, magic }
    }

    pub fn broadcast (&self, tx: &Transaction) -> Result<(), SPVError> {
        let msg = NetworkMessage::Tx((*tx).clone());
        for (_, peer) in self.peers.lock().unwrap().iter() {
            if peer.tx.unbounded_send(RawNetworkMessage { magic: self.magic, payload: msg.clone()}).is_err() {
                return Err(SPVError::Generic(format!("can not speak to peer={}", peer.remote_addr)))
            }
        }
        Ok(())
    }
}

