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
//! # Bitcoin SPV client node
//!
//! Implements a node that reacts to network messages and serves higher application
//! layer with a fresh view of the Bitcoin blockchain.
//!


use bitcoin::blockdata::block::{Block, LoneBlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::*;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;
use bitcoin::util;
use bitcoin_chain::blockchain::Blockchain;
use database::DB;
use error::SPVError;
use connector::LightningConnector;
use lightning::chain::chaininterface::BroadcasterInterface;
use p2p::{P2P, PeerId, PeerMap};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::sync::{RwLock, Mutex};
use std::collections::HashMap;
use futures::executor::ThreadPool;
use futures::{Future, Async};
use futures::future;
use futures_timer::Interval;
use std::time::Duration;
use futures::executor::Executor;

// peer is considered stale and banned if not
// sending valuable data within below number of minutes.
const STALE_PEER_MINUTES: u64 = 5;

/// The node replies with this process result to messages
pub enum ProcessResult {
    /// Acknowledgment
    Ack,
    /// Acknowledgment, P2P should indicate the new height in future version messages
    Height(u32),
    /// message ignored
    Ignored,
    /// increase ban score
    Ban(u32)
}


/// a helper class to implement LightningConnector
pub struct Broadcaster{
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
    // the connected P2P network
    p2p: Arc<P2P>,
    // peer map shared with P2P and the LightningConnector's broadcaster
    peers: Arc<RwLock<PeerMap>>,
    // type of the connected network
    network: Network,
    // the in-memory blockchain storing headers
    blockchain: Mutex<Blockchain>,
    // the persistent blockchain storing previously downloaded header and blocks
    db: Arc<Mutex<DB>>,
    // connector serving Layer 2 network
    connector: Arc<LightningConnector>,
    // unix time stamp of birth. Do not process blocks before this time point, but strictly after.
	birth: u32,
    // thread pool for tasks
    thread_pool: Arc<Mutex<ThreadPool>>,
    // last talked to peer
    last_talked: Arc<Mutex<HashMap<PeerId, u64>>>
}

impl Node {
    /// Create a new local node
    pub fn new(p2p: Arc<P2P>, network: Network, db: Arc<Mutex<DB>>, birth: u32, peers: Arc<RwLock<PeerMap>>,
        thread_pool: Arc<Mutex<ThreadPool>>) -> Node {
        let connector = LightningConnector::new(Arc::new(Broadcaster{peers: peers.clone ()}));
        Node {
            p2p,
            peers,
            network,
            blockchain: Mutex::new(Blockchain::new(network)),
            db,
            connector: Arc::new(connector),
	        birth,
            thread_pool,
            last_talked: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    /// Load headers from database
    pub fn load_headers(&self) -> Result<(), SPVError> {
        info!("loading headers from database...");
        // always lock blockchain before db
        let mut blockchain = self.blockchain.lock().unwrap();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if let Ok(tip) = tx.get_tip() {
            let mut n = 0;
            let genesis = genesis_block(self.network);
            info!("reading headers ...");
            let headers = tx.get_headers(&genesis.bitcoin_hash(), &tip)?;
            info!("building in-memory header chain ...");
            for header in headers {
                if blockchain.add_header(header).is_ok() {
                    n += 1;
                }
            }
            info!("loaded {} headers from database", n);
        } else {
            info!("no headers in the database");
        }
        tx.rollback()?;
        Ok(())
    }

	/// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pid: PeerId) -> Result<ProcessResult, SPVError> {
        use futures::StreamExt;

        self.get_headers(pid)?;

        let last_talked = self.last_talked.clone();
        let p2p = self.p2p.clone();

        let stale_watcher = Box::new(
            future::poll_fn (move |ctx| {
                let lt = last_talked.clone();
                let p2p2 = p2p.clone();
                Interval::new(Duration::from_secs(STALE_PEER_MINUTES * 60))
                    .for_each(move |_| {
                        if let Some (last_seen) = lt.lock().unwrap().get(&pid) {
                            if *last_seen < now () - STALE_PEER_MINUTES * 60 {
                                info! ("stale peer banned peer={}", pid);
                                p2p2.ban(pid).unwrap_or(());
                            }
                        }
                        Ok(())
                    }).poll(ctx).unwrap();
                Ok(Async::Pending)
            }));


        self.thread_pool.lock().unwrap().spawn(stale_watcher)
            .map_err (|_| SPVError::Generic("can not spawn tasks".to_owned()))?;

        Ok(ProcessResult::Ack)
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, _pid: PeerId) -> Result<ProcessResult, SPVError> {
        Ok(ProcessResult::Ack)
    }

    /// Process incoming messages
    pub fn process(&self, msg: &NetworkMessage, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let ret = match msg {
            &NetworkMessage::Ping(nonce) => self.ping(nonce, peer),
            &NetworkMessage::Headers(ref v) => self.headers(v, peer),
            &NetworkMessage::Block(ref b) => self.block(b, peer),
            &NetworkMessage::Inv(ref v) => self.inv(v, peer),
            &NetworkMessage::Addr(ref v) => self.addr(v, peer),
            _ => Ok(ProcessResult::Ban(1))
        };
        match ret {
           Ok(ProcessResult::Ack) => {
               self.last_talked.lock().unwrap().insert(peer, now ());
           },
            _ => {}
        }
        ret
    }

    // received ping
	fn ping (&self, nonce: u64, peer :PeerId) -> Result<ProcessResult, SPVError> {
        // send pong
		self.send(peer, &NetworkMessage::Pong(nonce))
	}

    // process headers message
	fn headers(&self, headers: &Vec<LoneBlockHeader>, peer: PeerId) -> Result<ProcessResult, SPVError> {
		if headers.len() > 0 {
			// blocks we want to download
			let mut ask_for_blocks = Vec::new();
            // headers to unwind due to re-org
			let mut disconnected_headers = Vec::new();
            // current height
			let height;
            // some received headers were not yet known
            let mut some_new = false;
			{
				// new scope to limit lock

				// always lock blockchain before db to avoid deadlock (if need to lock both)
				let mut blockchain = self.blockchain.lock().unwrap();

				let mut db = self.db.lock().unwrap();
				let tx = db.transaction()?;
                let mut tip_moved = false;

				for header in headers {
					let old_tip = blockchain.best_tip_hash();
					// add to in-memory blockchain - this also checks proof of work
                    match blockchain.add_header(header.header) {
                        Ok(_) => {
                            // this is a new header, not previously stored
                            let new_tip = blockchain.best_tip_hash();
                            tip_moved = tip_moved || new_tip != old_tip;
                            let header_hash = header.header.bitcoin_hash();
                            // ask for blocks after birth
                            if header.header.time > self.birth && new_tip == header_hash {
                                ask_for_blocks.push(new_tip);
                            }

                            tx.insert_header(&header.header)?;
                            some_new = true;

                            if header_hash == new_tip && header.header.prev_blockhash != old_tip {
                                // this is a re-org. Compute headers to unwind
                                for orphan_block in blockchain.rev_stale_iter(old_tip) {
                                    disconnected_headers.push(orphan_block.header);
                                }
                            }
                        }
                        Err(util::Error::SpvBadProofOfWork) => {
                            info!("Incorrect POW, banning peer={}", peer);
                            return Ok(ProcessResult::Ban(100))
                        },
                        Err(_) => return Ok(ProcessResult::Ignored)
                    }
				}
				let new_tip = blockchain.best_tip_hash();
				height = blockchain.get_block(new_tip).unwrap().height;

                if tip_moved {
                    tx.set_tip(&new_tip)?;

                    tx.commit()?;
                    info!("received {} headers new tip={} from peer={}", headers.len(),
                          blockchain.best_tip_hash(), peer);
                } else {
                    tx.commit()?;
                    debug!("received {} known or orphan headers from peer={}", headers.len(), peer);
                    ask_for_blocks.clear();
                    return Ok(ProcessResult::Ban(5))
                }
			}

            // notify lightning connector of disconnected blocks
			for header in disconnected_headers {
				self.connector.block_disconnected(&header);
			}
            // ask for new blocks on trunk
            self.get_blocks(peer, ask_for_blocks)?;

            // ask if peer knows even more
            if some_new {
                self.get_headers(peer)?;
            }
			Ok(ProcessResult::Height(height))
		} else {
			Ok(ProcessResult::Ack)
		}
	}

    // process an incoming block
	fn block (&self, block: &Block, _: PeerId)-> Result<ProcessResult, SPVError> {
		let blockchain = self.blockchain.lock().unwrap();
		// header should be known already, otherwise it might be spam
		let block_node = blockchain.get_block(block.bitcoin_hash());
		if block_node.is_some() {
			let bn = block_node.unwrap();
			if bn.block.txdata.is_empty() && bn.is_on_main_chain(&blockchain) {
				// limit context
				{
					// store a block if it is on the chain with most work
					let mut db = self.db.lock().unwrap();
					let tx = db.transaction()?;
					tx.insert_block(&block)?;
					tx.commit()?;
				}
				// send new block to lighning connector
				self.connector.block_connected(&block, bn.height);
			}
            return Ok(ProcessResult::Ack)
		}
		Ok(ProcessResult::Ban(10))
	}

    // process an incoming inventory announcement
	fn inv(&self, v: &Vec<Inventory>, peer: PeerId) -> Result<ProcessResult, SPVError> {
		for inventory in v {
            // only care of blocks
			if inventory.inv_type == InvType::Block || inventory.inv_type == InvType::WitnessBlock
				&& self.blockchain.lock().unwrap().get_block(inventory.hash).is_none() {
				// ask for header(s) if observing a new block
				self.get_headers(peer)?;
				return Ok(ProcessResult::Ack);
			}
            else {
                // do not spam us with transactions
                debug!("received unwanted inv {:?} peer={}", inventory.inv_type, peer);
                return Ok(ProcessResult::Ban(10))
            }
		}
		Ok(ProcessResult::Ignored)
	}

    // process incoming addr messages
	fn addr (&self, v: &Vec<(u32, Address)>, peer: PeerId)  -> Result<ProcessResult, SPVError> {
        let mut result = ProcessResult::Ignored;
        // store if interesting, that is ...
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
		let mut db = self.db.lock().unwrap();
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

    /// get the blocks we are interested in
    fn get_blocks(&self, peer: PeerId, blocks: Vec<Sha256dHash>) -> Result<ProcessResult, SPVError> {
        if blocks.len () > 0 {
            let mut invs = Vec::new();
            for b in blocks {
                invs.push(Inventory {
                    inv_type: InvType::WitnessBlock,
                    hash: b,
                });
            }
            return self.send(peer, &NetworkMessage::GetData(invs))
        }
        Ok(ProcessResult::Ack)
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let locator = self.blockchain.lock().unwrap().locator_hashes();
        if locator.len() > 0 {
            let last = if locator.len() > 0 {
                *locator.last().unwrap()
            } else {
                Sha256dHash::default()
            };
            return self.send(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)))
        }
        Ok(ProcessResult::Ack)
    }

    /// send to peer
    fn send(&self, peer: PeerId, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        if let Some(sender) = self.peers.read().unwrap().get(&peer) {
            sender.lock().unwrap().send (msg)?;
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
    pub fn broadcast_transaction(&self, tx: &Transaction) -> Result<ProcessResult, SPVError>  {
        self.broadcast(&NetworkMessage::Tx(tx.clone()))
    }

	/// retrieve the interface for lighning network
    pub fn get_chain_watch_interface(&self) -> Arc<LightningConnector> {
        self.connector.clone()
    }

	/// retrieve the interface a higher application layer e.g. lighning may use to send transactions to the network
    #[allow(dead_code)]
    pub fn get_broadcaster (&self) -> Arc<Broadcaster> {
        self.connector.get_broadcaster()
    }
}

#[inline]
fn now () -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}