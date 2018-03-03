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

lazy_static! {
    static ref STDRNG : Mutex<StdRng> = Mutex::new(StdRng::new().unwrap());
}

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
    pub peers: Mutex<HashMap<SocketAddr, Peer>>,
    pub blockchain: Mutex<Blockchain>,
    pub db: Mutex<DB>,
}

impl Node {
    /// Create a new local node for a network that uses the given database
    pub fn new(network: Network, db: DB) -> Node {
        Node {
            network,
            height: AtomicUsize::new(0),
            nonce: STDRNG.lock().unwrap().next_u64(),
            peers: Mutex::new(HashMap::new()),
            blockchain: Mutex::new(Blockchain::new(network)),
            db : Mutex::new(db),
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
                    {
                        // new scope to limit lock

                        // always lock blockchain before db to avoid deadlock (if need to lock both)
                        let mut blockchain = self.blockchain.lock().unwrap();

                        let mut db = self.db.lock().unwrap();
                        let tx = db.transaction()?;

                        let mut last_tip = Sha256dHash::default();
                        for header in v {
                            // add to in-memory blockchain - this also checks work
                            if blockchain.add_header(header.header).is_ok() {
                                // if successful also add to db
                                tx.insert_header(&header.header)?;

                                // not older than a day, themn also request the full block
                                // this is temporary until BIP157 & BIP158 become available
                                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
                                if header.header.time > now - 60*60*24 && blockchain.best_tip_hash () != last_tip {
                                    last_tip = header.header.bitcoin_hash();
                                    ask_for_blocks.push (last_tip);
                                }
                            }
                        }
                        tx.set_tip(&blockchain.best_tip_hash())?;
                        tx.commit()?;
                        info!("add {} headers tip={} from peer={}", v.len(),
                              blockchain.best_tip_hash(), peer.remote_addr);
                    }
                    self.get_blocks(peer, ask_for_blocks)?;
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
                            // store a block if it is on the chain with most work
                            let mut db = self.db.lock().unwrap();
                            let tx = db.transaction()?;
                            tx.insert_block(&b)?;
                            tx.commit()?;
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
