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


use bitcoin_chain::blockchain::Blockchain;
use bitcoin::blockdata::block::{Block, LoneBlockHeader};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::constants::Network;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::*;
use bitcoin::network::message_network::*;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;
use database::DB;
use dispatcher::{Tx, ProcessResult};
use error::SPVError;
use lightning::chain::chaininterface::BroadcasterInterface;
use lighningconnector::LightningConnector;
use std::collections::HashMap;
use std::io;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::RwLock;

/// a connected peer
pub struct Peer {
    tx: Tx,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    version: VersionMessage,
    banscore: AtomicUsize,
}

impl Peer {
	/// construct a peer
    pub fn new(tx: Tx, local_addr: SocketAddr, remote_addr: SocketAddr, version: VersionMessage) -> Peer {
        Peer {
            tx,
            local_addr,
            remote_addr,
            version,
            banscore: AtomicUsize::new(0),
        }
    }

    /// increment ban score for a misbehaving peer. Ban if score reaches 100
    fn ban(peer: &Peer, addscore: u16) -> Result<(), io::Error> {
        let oldscore = peer.banscore.fetch_add(addscore as usize, Ordering::Relaxed);
        if oldscore + addscore as usize >= 100 {
            info!("banned peer={}", peer.remote_addr);
            Err(io::Error::new(io::ErrorKind::Other, format!("banned peer={}", peer.remote_addr)))
        } else {
            Ok(())
        }
    }
}

/// The local node processing incoming messages
pub struct Node {
    network: Network,
    peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
    blockchain: Mutex<Blockchain>,
    db: Mutex<DB>,
    connector: Arc<LightningConnector>,
	birth: u32
}

impl Node {
    /// Create a new local node for a network that uses the given database
    pub fn new(network: Network, db: DB, birth: u32) -> Node {
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let connector = LightningConnector::new(
            Arc::new(Broadcaster::new(peers.clone())));
        Node {
            network,
            peers,
            blockchain: Mutex::new(Blockchain::new(network)),
            db: Mutex::new(db),
            connector: Arc::new(connector),
	        birth
        }
    }

    /// Load headers from database
    pub fn load_headers(&self) -> Result<(), SPVError> {
        info!("loading headers from database...");
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if let Ok(tip) = tx.get_tip() {
            let mut n = 0;
            let genesis = genesis_block(self.network);
            let mut blockchain = self.blockchain.lock().unwrap();
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
    pub fn connected(&self, version: VersionMessage, local_addr: &SocketAddr, remote_addr: &SocketAddr, tx: Tx) -> Result<ProcessResult, SPVError> {
        let mut peers = self.peers.write().unwrap();
        let peer = Peer::new(tx, *local_addr, *remote_addr, version);
        peers.insert(*remote_addr, peer);
        self.get_headers(peers.get(remote_addr).unwrap())
    }

	/// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, remote_addr: &SocketAddr) {
        let mut peers = self.peers.write().unwrap();
        peers.remove(remote_addr);
    }

    /// Process incoming messages
    pub fn process(&self, msg: &NetworkMessage, remote_addr: &SocketAddr) -> Result<ProcessResult, SPVError> {
        if let Some(peer) = self.peers.read().unwrap().get(remote_addr) {
            self.process_for_peer(msg, peer)
        } else {
            Err(SPVError::UnknownPeer(*remote_addr))
        }
    }

	fn ping (&self, nonce: u64, peer :&Peer) -> Result<ProcessResult, SPVError> {
		self.reply(peer, &NetworkMessage::Pong(nonce))
	}

	fn headers(&self, headers: &Vec<LoneBlockHeader>, peer: &Peer) -> Result<ProcessResult, SPVError> {
		if headers.len() > 0 {
			// blocks we want to download
			let mut ask_for_blocks = Vec::new();
			let mut disconnected_headers = Vec::new();
			let height;
			{
				// new scope to limit lock

				// always lock blockchain before db to avoid deadlock (if need to lock both)
				let mut blockchain = self.blockchain.lock().unwrap();

				let mut db = self.db.lock().unwrap();
				let tx = db.transaction()?;

				for header in headers {
					let old_tip = blockchain.best_tip_hash();
					// add to in-memory blockchain - this also checks proof of work
					if blockchain.add_header(header.header).is_ok() {
						// this is a new header, not previously stored
						let new_tip = blockchain.best_tip_hash();
						let header_hash = header.header.bitcoin_hash();
						if header.header.time > self.birth - 60 * 60 * 3 && new_tip == header_hash {
							// if time stamp is not older than three hours before our birth day and extending the trunk
							// then ask for the block
							ask_for_blocks.push(new_tip);
						}

						tx.insert_header(&header.header)?;

						if header_hash == new_tip && header.header.prev_blockhash != old_tip {
							// this is a re-org. Compute headers to unwind
							for orphan_block in blockchain.rev_stale_iter(old_tip) {
								disconnected_headers.push(orphan_block.header);
							}
						}
					}
				}
				let new_tip = blockchain.best_tip_hash();
				height = blockchain.get_block(new_tip).unwrap().height;

				tx.set_tip(&new_tip)?;

				tx.commit()?;
				info!("add {} headers tip={} from peer={}", headers.len(),
				      blockchain.best_tip_hash(), peer.remote_addr);
			}

			for header in disconnected_headers {
				self.connector.block_disconnected(&header);
			}
			// ask for new blocks on trunk
			self.get_blocks(peer, ask_for_blocks)?;
			// ask if peer knows even more
			self.get_headers(peer)?;
			Ok(ProcessResult::Height(height))
		} else {
			Ok(ProcessResult::Ack)
		}
	}

	fn block (&self, block: &Block, _: &Peer)-> Result<ProcessResult, SPVError> {
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
		}
		Ok(ProcessResult::Ack)
	}

	fn inv(&self, v: &Vec<Inventory>, peer: &Peer) -> Result<ProcessResult, SPVError> {
		for inventory in v {
			if inventory.inv_type == InvType::Block
				&& self.blockchain.lock().unwrap().get_block(inventory.hash).is_none() {
				// ask for header(s) if observing a new block
				self.get_headers(peer)?;
				break;
			}
		}
		Ok(ProcessResult::Ack)
	}

    fn process_for_peer(&self, msg: &NetworkMessage, peer: &Peer) -> Result<ProcessResult, SPVError> {
        match msg {
            &NetworkMessage::Ping(nonce) => self.ping(nonce, peer),
            &NetworkMessage::Headers(ref v) => self.headers(v, peer),
            &NetworkMessage::Block(ref b) => self.block(b, peer),
            &NetworkMessage::Inv(ref v) => self.inv(v, peer),
            _ => Ok(ProcessResult::Ignored)
        }
    }

    /// get the blocks we are interested in
    fn get_blocks(&self, peer: &Peer, blocks: Vec<Sha256dHash>) -> Result<ProcessResult, SPVError> {
        let mut invs = Vec::new();
        for b in blocks {
            invs.push(Inventory {
                inv_type: InvType::Block,
                hash: b,
            });
        }
        self.reply(peer, &NetworkMessage::GetData(invs))
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: &Peer) -> Result<ProcessResult, SPVError> {
        let locator = self.blockchain.lock().unwrap().locator_hashes();
        let last = if locator.len() > 0 {
            *locator.last().unwrap()
        } else {
            Sha256dHash::default()
        };
        self.reply(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)))
    }

    /// Reply to peer
    fn reply(&self, peer: &Peer, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        if peer.tx.unbounded_send((*msg).clone()).is_err() {
            Err(SPVError::Generic(format!("can not speak to peer={}", peer.remote_addr)))
        } else {
            Ok(ProcessResult::Ack)
        }
    }

    /// send a new transaction to all peers
    fn send_transaction(&self, tx: Transaction) -> Result<ProcessResult, SPVError> {
        self.broadcast(&NetworkMessage::Tx(tx))
    }

    /// send the same message to all connected peers
    fn broadcast(&self, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        for (_, peer) in self.peers.read().unwrap().iter() {
            self.reply(peer, msg)?;
        }
        Ok(ProcessResult::Ack)
    }

	/// retrieve the interface for lighning network
    pub fn get_chain_watch_interface(&self) -> Arc<LightningConnector> {
        self.connector.clone()
    }

	/// retrieve the interface a higher application layer e.g. lighning may use to send transactions to the network
    pub fn get_broadcaster (&self) -> Arc<Broadcaster> {
        self.connector.get_broadcaster()
    }
}

/// a helper class to implement LightningConnector
pub struct Broadcaster {
    peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
}

impl Broadcaster {
    /// create a broadcaster
	pub fn new(peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>) -> Broadcaster {
        Broadcaster { peers }
    }
}

impl BroadcasterInterface for Broadcaster {
    fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), Box<Error>> {
        let msg = NetworkMessage::Tx((*tx).clone());
        for (_, peer) in self.peers.read().unwrap().iter() {
            if peer.tx.unbounded_send(msg.clone()).is_err() {
                return Err(Box::new(SPVError::Generic(format!("can not speak to peer={}", peer.remote_addr))));
            }
        }
        Ok(())
    }
}

