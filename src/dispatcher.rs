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
//! # Messsage dispatcher
//!


use connector::LightningConnector;
use configdb::SharedConfigDB;
use chaindb::SharedChainDB;
use error::SPVError;
use p2p::{PeerId, PeerMessageSender, PeerMessageReceiver, P2PControlSender, P2PControl, PeerMessage};
use filtercalculator::FilterCalculator;
use headerdownload::HeaderDownload;
use filterserver::FilterServer;
use blockserver::BlockServer;
use timeout::{Timeout, SharedTimeout};
use ping::Ping;

use bitcoin::{
    blockdata::{
        block::{Block, LoneBlockHeader}
    },
    network::{
        address::Address,
        constants::Network,
        message::NetworkMessage,
        message_blockdata::*,
    },
};

use std::{
    thread,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH}
};


/// The local node processing incoming messages
pub struct Dispatcher {
    p2p: P2PControlSender,
    // the configuration db
    configdb: SharedConfigDB,
    // the blockchain db
    chaindb: SharedChainDB,
    header_downloader: PeerMessageSender,
    // block downloader sender
    filter_calculator: PeerMessageSender,
    // filter server
    filter_server: PeerMessageSender,
    // block server
    block_server: PeerMessageSender,
    // pinger
    ping: PeerMessageSender,
    // peer timeout tracker
    timeout: SharedTimeout,
    // lightning connector
    connector: Arc<LightningConnector>
}

impl Dispatcher {
    /// Create a new local node
    pub fn new(network: Network, configdb: SharedConfigDB, chaindb: SharedChainDB, server: bool, connector: Arc<LightningConnector>, p2p: P2PControlSender, incoming: PeerMessageReceiver) -> Arc<Dispatcher> {

        let timeout = Arc::new(Mutex::new(Timeout::new(p2p.clone())));

        let header_downloader = HeaderDownload::new(chaindb.clone(), p2p.clone(), timeout.clone());

        let ping = Ping::new(p2p.clone(), timeout.clone());

        let filter_calculator = if server {
            FilterCalculator::new(network, chaindb.clone(), p2p.clone(), timeout.clone())
        }
        else {
            PeerMessageSender::dummy()
        };

        let filter_server = if server {
            FilterServer::new(chaindb.clone(), p2p.clone())
        } else {
            PeerMessageSender::dummy()
        };

        let block_server = if server {
            BlockServer::new(chaindb.clone(), p2p.clone())
        } else {
            PeerMessageSender::dummy()
        };


        let dispatcher = Arc::new(Dispatcher {
            p2p,
            configdb,
            chaindb,
            header_downloader,
            filter_calculator,
            filter_server,
            block_server,
            ping,
            timeout,
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
    pub fn init(&self, server: bool) -> Result<(), SPVError> {
        self.chaindb.write().unwrap().init(server)?;
        Ok(())
    }

    /// called from dispatcher whenever a new peer is connected (after handshake is successful)
    pub fn connected(&self, pm: PeerMessage) -> Result<(), SPVError> {
        debug!("connected peer={}", pm.peer_id());
        self.header_downloader.send (pm.clone());
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
            NetworkMessage::Ping(nonce) => {
                self.p2p.send_network(peer, NetworkMessage::Pong(nonce));
                Ok(())
            },
            NetworkMessage::Pong(_) => {
                self.ping.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::Headers(_) => {
                self.header_downloader.send_network(peer, msg);
                self.filter_calculator.send_network(peer, NetworkMessage::Ping(0));
                Ok(())
            },
            NetworkMessage::Block(_) => {
                self.filter_calculator.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::Inv(_) => {
                self.header_downloader.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::Addr(ref v) => self.addr(v, peer),

            NetworkMessage::GetHeaders(_) =>{
                self.block_server.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::GetBlocks(_) => {
                self.block_server.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::GetData(_) => {
                self.block_server.send_network(peer, msg);
                Ok(())
            },

            NetworkMessage::GetCFilters(_) => {
                self.filter_server.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::GetCFHeaders(_) => {
                self.filter_server.send_network(peer, msg);
                Ok(())
            },
            NetworkMessage::GetCFCheckpt(_) => {
                self.filter_server.send_network(peer, msg);
                Ok(())
            }
            _ => { self.p2p.send(P2PControl::Ban(peer, 1)); Ok(()) }
        }?)
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
}
