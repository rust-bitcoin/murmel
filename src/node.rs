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
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::*;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util;
use bitcoin::util::hash::Sha256dHash;
use bitcoin_chain::blockchain::Blockchain;
use blockfilter::BlockFilter;
use blockfilter::UTXOAccessor;
use connector::LightningConnector;
use database::{DB, DBTX};
use error::SPVError;
use futures::task::Context;
use lightning::chain::chaininterface::BroadcasterInterface;
use p2p::{P2P, PeerId, PeerMap};
use tasks::Tasks;
use rand::Rng;
use rand::thread_rng;
use std::cell::Cell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::io;
use std::sync::{Mutex, RwLock};
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::cmp::min;


// peer is considered stale and banned if not
// sending valuable data within below number of seconds.
const STALE_PEER_SECONDS: u32 = 30;

// number of blocks to download at a single operation
const BLOCK_DOWNLOAD_BATCH: usize = 100;

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
    // the in-memory blockchain storing headers
    blockchain: Mutex<Blockchain>,
    // the persistent blockchain storing previously downloaded header and blocks
    db: Arc<Mutex<DB>>,
    // connector serving Layer 2 network
    connector: Arc<LightningConnector>,
    // is this a server node?
    server: bool,
    // blocks to download
    want_blocks: Mutex<VecDeque<Sha256dHash>>,
    // waker to tasks
    tasks: Tasks,
    // peer used for block download
    download_peer: Mutex<Cell<Option<PeerId>>>,
    // expecting to receive these blocks
    expecting_blocks: Mutex<VecDeque<Sha256dHash>>,

    temp_processed: Mutex<HashSet<Sha256dHash>>
}

impl Node {
    /// Create a new local node
    pub fn new(p2p: Arc<P2P>, network: Network, db: Arc<Mutex<DB>>, server: bool, peers: Arc<RwLock<PeerMap>>) -> Node {
        let connector = LightningConnector::new(Arc::new(Broadcaster { peers: peers.clone() }));
        Node {
            inner: Arc::new(Inner {
                p2p,
                peers,
                network,
                blockchain: Mutex::new(Blockchain::new(network)),
                db,
                connector: Arc::new(connector),
                server,
                want_blocks: Mutex::new(VecDeque::new()),
                tasks: Tasks::new(),
                download_peer: Mutex::new(Cell::new(None)),
                expecting_blocks: Mutex::new(VecDeque::new()),
                temp_processed: Mutex::new(HashSet::new())
            })
        }
    }

    /// Initialize node before P2P communication starts
    pub fn init_before_p2p(&self, ctx: &mut Context) {
        trace!("initialize node before P2P")
    }

    /// Load headers from database
    pub fn load_headers(&self) -> Result<(), SPVError> {
        info!("loading headers from database...");
        // always lock blockchain before db
        let mut blockchain = self.inner.blockchain.lock().unwrap();
        let mut db = self.inner.db.lock().unwrap();
        let tx = db.transaction()?;
        info!("reading headers ...");
        let headers = tx.get_headers(&mut blockchain)?;
        if self.inner.server {

        }
        info!("read {} headers from the database", headers);
        tx.commit()?;
        Ok(())
    }

    /// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pid: PeerId, ctx: &mut Context) -> Result<ProcessResult, SPVError> {
        self.get_headers(pid)?;

        let node = self.clone();

        // a never ending task that downloads blocks
        // use self.download_blocks to pass work to it
        self.inner.tasks.spawn_no_error(ctx, "block downloader",
                                        move |ctx| node.task_block_download(ctx));

        Ok(ProcessResult::Ack)
    }

    // body od the "block downloader" task
    fn task_block_download (&self, ctx: &mut Context) -> Result<bool, SPVError> {
        // todos in want
        let mut want = self.inner.want_blocks.lock().unwrap();
        if !want.is_empty() {
            // choose peer
            if let Some(peer_id) = self.get_download_peer_id() {

                // take no more then BLOCK_DOWNLOAD_BATCH blocks for a batch
                let batch_range = 0 .. min(BLOCK_DOWNLOAD_BATCH, want.len());
                let batch = want.drain(batch_range).collect::<Vec<_>>();
                let batch2 = batch.clone();

                let node = self.clone();
                let node2 = self.clone();
                // spawn the task downloading the batch
                self.inner.tasks.spawn_with_timeout(ctx, "block batch", STALE_PEER_SECONDS,
                                                    move |ctx| {
                                                        node.task_block_download_batch(ctx, peer_id, batch.clone())
                                                    },
                                                    move |error| {
                                                        // the peer did not send the batch within STALE_PEER_SECONDS
                                                        node2.task_block_download_failed(error, peer_id, batch2.clone());
                                                    });
            }
        }
        // this task never ends, park it.
        Ok(false)
    }

    // decide if the block was fully processed
    fn is_processed (&self, block: &Sha256dHash) -> bool {
        self.inner.temp_processed.lock().unwrap().contains(block)
    }

    // download a batch of blocks
    fn task_block_download_batch(&self, ctx: &mut Context, peer_id: PeerId, batch: Vec<Sha256dHash>) -> Result<bool, SPVError> {
        let mut expecting = self.inner.expecting_blocks.lock().unwrap();
        if expecting.is_empty() {
            // if not yet expecting to receive
            let peers = self.inner.peers.read().unwrap();
            if let Some(peer) = peers.get(&peer_id) {
                // filter out processed blocks and compile inventory request
                expecting.extend(batch.iter().filter(|h| !self.is_processed(*h)));
                let invs = expecting.iter()
                    .map(|hash| Inventory { inv_type: InvType::Block, hash: hash.clone() })
                    .collect::<Vec<_>>();
                if invs.len() > 0 {
                    // if any left ask the peer for it
                    peer.lock().unwrap().send(&NetworkMessage::GetData(invs))?;
                }
                return Ok(false);
            }
            else {
                // lost downloading peer
                expecting.clear();
            }
        }
        else {
            // expecting some but not yet received -> park this task
            return Ok(false);
        }
        // done with this task. wake up "block downloader" to get a new batch
        self.inner.tasks.wake("block downloader");
        Ok(true)
    }

    fn task_block_download_failed (&self, error: SPVError, peer_id: PeerId, batch: Vec<Sha256dHash>) {
        info!("ban slow peer {}", peer_id);
        self.inner.p2p.ban(peer_id).unwrap_or(());
        // push back failed batch to want
        let mut want = self.inner.want_blocks.lock().unwrap();
        for h in batch.iter().rev() {
            want.push_front(*h);
        }
        // wake up downloader
        self.inner.tasks.wake("block downloader");
    }

    fn download_blocks(&self, blocks: Vec<Sha256dHash>) {
        // add to wanted blocks
        self.inner.want_blocks.lock().unwrap().extend(blocks);
        // wake downloader
        self.inner.tasks.wake("block downloader");
    }

    fn get_download_peer_id(&self) -> Option<PeerId> {
        let peers = self.inner.peers.read().unwrap();
        let download_peer = self.inner.download_peer.lock().unwrap();
        // stick with current download peer if available
        if let Some (peer) = download_peer.get() {
            return Some(peer);
        }
        else {
            // otherwise chose and store a random one
            let mut rng = thread_rng();
            let peer_index = rng.next_u64() as usize % peers.len();
            for (i, v) in peers.keys().enumerate() {
                if i == peer_index {
                    download_peer.replace(Some(*v));
                    return Some(*v);
                }
            }
            return None;
        }
    }

    /// called from dispatcher whenever a peer is disconnected
    pub fn disconnected(&self, pid: PeerId) -> Result<ProcessResult, SPVError> {
        if let Some(downloading_peer) = self.inner.download_peer.lock().unwrap().get() {
            if downloading_peer == pid {
                self.inner.expecting_blocks.lock().unwrap().clear();
                self.inner.tasks.wake("block downloader");
            }
        }
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
            // blocks we want to download
            let mut ask_for_blocks = Vec::new();
            // headers to unwind due to re-org
            let mut disconnected_headers = Vec::new();
            // current height
            let height;
            // some received headers were not yet known
            let mut some_new = false;
            let mut tip_moved = false;
            {
                // new scope to limit lock

                // always lock blockchain before db to avoid deadlock (if need to lock both)
                let mut blockchain = self.inner.blockchain.lock().unwrap();

                let mut db = self.inner.db.lock().unwrap();
                let tx = db.transaction()?;

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
                            if self.inner.server && new_tip == header_hash {
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
                            return Ok(ProcessResult::Ban(100));
                        }
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
                    return Ok(ProcessResult::Ban(5));
                }
            }

            // notify lightning connector of disconnected blocks
            for header in disconnected_headers {
                // limit context
                self.inner.connector.block_disconnected(&header);
            }
            // ask for new blocks on trunk
            self.download_blocks(ask_for_blocks);

            // ask if peer knows even more
            if some_new {
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
    fn block(&self, block: &Block, peer: PeerId) -> Result<ProcessResult, SPVError> {
        if let Some(download_peer) = self.inner.download_peer.lock().unwrap().get() {
            if peer == download_peer {
                // if from download peer
                let mut expecting = self.inner.expecting_blocks.lock().unwrap();
                // expect to see next
                if let Some(next) = expecting.pop_front() {
                    if next != block.bitcoin_hash() {
                        expecting.push_front(next);
                    }
                    else {
                        // received some expected, wake up batch
                        self.inner.tasks.wake("block batch");
                    }
                }
            }
        }
        let blockchain = self.inner.blockchain.lock().unwrap();
        // header should be known already, otherwise it might be spam
        let block_node = blockchain.get_block(block.bitcoin_hash());
        if block_node.is_some() {
            let bn = block_node.unwrap();
            if bn.is_on_main_chain(&blockchain) {
                // send new block to lighning connector
                self.inner.connector.block_connected(&block, bn.height);
            }
            info!("processed block {}", block.bitcoin_hash());
            self.inner.temp_processed.lock().unwrap().insert(block.bitcoin_hash());
            return Ok(ProcessResult::Ack);
        }
        Ok(ProcessResult::Ignored)
    }

    // process an incoming inventory announcement
    fn inv(&self, v: &Vec<Inventory>, peer: PeerId) -> Result<ProcessResult, SPVError> {
        for inventory in v {
            // only care of blocks
            if inventory.inv_type == InvType::Block
                && self.inner.blockchain.lock().unwrap().get_block(inventory.hash).is_none() {
                // ask for header(s) if observing a new block
                self.get_headers(peer)?;
                return Ok(ProcessResult::Ack);
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

    /// get the blocks we are interested in
    fn get_blocks(&self, peer: PeerId, blocks: Vec<Sha256dHash>) -> Result<ProcessResult, SPVError> {
        if blocks.len() > 0 {
            let mut invs = Vec::new();
            for b in blocks {
                invs.push(Inventory {
                    inv_type: InvType::WitnessBlock,
                    hash: b,
                });
            }
            return self.send(peer, &NetworkMessage::GetData(invs));
        }
        Ok(ProcessResult::Ack)
    }

    /// get headers this peer is ahead of us
    fn get_headers(&self, peer: PeerId) -> Result<ProcessResult, SPVError> {
        let locator = self.inner.blockchain.lock().unwrap().locator_hashes();
        if locator.len() > 0 {
            let last = if locator.len() > 0 {
                *locator.last().unwrap()
            } else {
                Sha256dHash::default()
            };
            return self.send(peer, &NetworkMessage::GetHeaders(GetHeadersMessage::new(locator, last)));
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

struct DBUTXOAccessor<'a> {
    pub tx: &'a DBTX<'a>,
    pub same_block_utxo: HashMap<(Sha256dHash, u32), (Script, u64)>,
}

impl<'a> DBUTXOAccessor<'a> {
    fn new(tx: &'a DBTX<'a>, block: &Block) -> DBUTXOAccessor<'a> {
        let mut acc = DBUTXOAccessor { tx, same_block_utxo: HashMap::new() };
        for t in &block.txdata {
            let id = t.txid();
            for (ix, o) in t.output.iter().enumerate() {
                acc.same_block_utxo.insert((id, ix as u32), (o.script_pubkey.clone(), o.value));
            }
        }
        acc
    }
}

impl<'a> UTXOAccessor for DBUTXOAccessor<'a> {
    fn get_utxo(&self, txid: &Sha256dHash, ix: u32) -> Result<(Script, u64), io::Error> {
        if let Some(utxo) = self.same_block_utxo.get(&(*txid, ix)) {
            return Ok(utxo.clone());
        }
        Ok(self.tx.get_utxo(txid, ix)?)
    }
}

#[inline]
fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}