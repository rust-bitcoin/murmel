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
use bitcoin_chain::blockchain::Blockchain;
use database::DB;
use error::SPVError;
use lighningconnector::LightningConnector;
use lightning::chain::chaininterface::BroadcasterInterface;
use p2p::{P2P, Peer};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;


/// The node replies with this process result to messages
pub enum ProcessResult {
    /// Acknowledgment
    Ack,
    /// Acknowledgment, dispatcher should indicate the new height in future version messages
    Height(u32),
    /// The message was ignored by the node
    Ignored,
    /// The node really does not like the message (or ban score limit reached), disconnect this rouge peer
    Disconnect,
}

/// The local node processing incoming messages
pub struct Node {
    p2p: Arc<P2P>,
    network: Network,
    blockchain: Mutex<Blockchain>,
    db: Arc<Mutex<DB>>,
    connector: Arc<LightningConnector>,
	birth: u32
}

impl Node {
    /// Create a new local node for a network that uses the given database
    pub fn new(p2p: Arc<P2P>, network: Network, db: Arc<Mutex<DB>>, birth: u32) -> Node {
        let connector = LightningConnector::new(Arc::new(Broadcaster{}));
        Node {
            p2p,
            network,
            blockchain: Mutex::new(Blockchain::new(network)),
            db,
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
    pub fn connected(&self, peer: &Peer) -> Result<ProcessResult, SPVError> {
        self.get_headers(peer)
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, _peer: &Peer) -> Result<ProcessResult, SPVError> {
        Ok(ProcessResult::Ack)
    }

    /// Process incoming messages
    pub fn process(&self, msg: &NetworkMessage, peer: &Peer) -> Result<ProcessResult, SPVError> {
        match msg {
            &NetworkMessage::Ping(nonce) => self.ping(nonce, peer),
            &NetworkMessage::Headers(ref v) => self.headers(v, peer),
            &NetworkMessage::Block(ref b) => self.block(b, peer),
            &NetworkMessage::Inv(ref v) => self.inv(v, peer),
            &NetworkMessage::Addr(ref v) => self.addr(v, peer),
            _ => Ok(ProcessResult::Ignored)
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
					if blockchain.add_header(header.header).is_ok() {
						// this is a new header, not previously stored
						let new_tip = blockchain.best_tip_hash();
                        tip_moved = tip_moved || new_tip != old_tip;
						let header_hash = header.header.bitcoin_hash();
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
				}
				let new_tip = blockchain.best_tip_hash();
				height = blockchain.get_block(new_tip).unwrap().height;

				tx.set_tip(&new_tip)?;

				tx.commit()?;

                if tip_moved {
                    info!("received {} headers new tip={} from peer={}", headers.len(),
                          blockchain.best_tip_hash(), peer.pid);
                } else {
                    debug!("received {} orphan headers from peer={}", headers.len(), peer.pid);
                    ask_for_blocks.clear();
                }
			}

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

	fn addr (&self, v: &Vec<(u32, Address)>, _peer: &Peer)  -> Result<ProcessResult, SPVError> {
		let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
		let mut db = self.db.lock().unwrap();
		let tx = db.transaction()?;
		for a in v.iter() {
            // if not tor
            if a.1.socket_addr().is_ok() {
                // if segwit full node and not older than 3 hours
                if a.1.services & 9 == 9 && a.0 > now - 3 * 60 * 30 {
                    tx.store_peer(&a.1, a.0, 0)?;
                    info!("stored address {:?}", a.1.socket_addr()?);
                }
            }
		}
		tx.commit()?;
		Ok(ProcessResult::Ack)
	}

    /// get the blocks we are interested in
    fn get_blocks(&self, peer: &Peer, blocks: Vec<Sha256dHash>) -> Result<ProcessResult, SPVError> {
        if blocks.len () > 0 {
            let mut invs = Vec::new();
            for b in blocks {
                invs.push(Inventory {
                    inv_type: InvType::WitnessBlock,
                    hash: b,
                });
            }
            return self.reply(peer, &NetworkMessage::GetData(invs))
        }
        Ok(ProcessResult::Ack)
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: &Peer) -> Result<ProcessResult, SPVError> {
        let locator = self.blockchain.lock().unwrap().locator_hashes();
        if locator.len() > 0 {
            let last = if locator.len() > 0 {
                *locator.last().unwrap()
            } else {
                Sha256dHash::default()
            };
            return self.reply(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)))
        }
        Ok(ProcessResult::Ack)
    }

    /// Reply to peer
    fn reply(&self, peer: &Peer, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        peer.send(msg)?;
        Ok(ProcessResult::Ack)
    }

    /// send a new transaction to all peers
    fn send_transaction(&self, tx: Transaction) -> Result<ProcessResult, SPVError> {
        self.broadcast(&NetworkMessage::Tx(tx))
    }

    /// send the same message to all connected peers
    fn broadcast(&self, msg: &NetworkMessage) -> Result<ProcessResult, SPVError> {
        self.p2p.broadcast(msg)?;
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
pub struct Broadcaster;

impl BroadcasterInterface for Broadcaster {
    fn broadcast_transaction(&self, tx: &Transaction) {
        // TODO
    }
}

