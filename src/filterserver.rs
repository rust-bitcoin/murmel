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
//! # Serve BIP157 requests
//!

use bitcoin::{
    BitcoinHash,
    network::message::NetworkMessage,
    network::message_filter::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters},
    util::hash::Sha256dHash
};
use chaindb::{ChainDB, SharedChainDB};
use chaindb::StoredFilter;
use error::MurmelError;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use std::{
    iter,
    sync::{mpsc, RwLockReadGuard},
    sync::Arc,
    thread
};

pub struct FilterServer {
    p2p: P2PControlSender,
    chaindb: SharedChainDB,
}


impl FilterServer {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut filterserver = FilterServer { chaindb, p2p };

        thread::spawn(move || { filterserver.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        while let Ok(msg) = receiver.recv() {
            if let Err(e) = match msg {
                PeerMessage::Message(pid, msg) => {
                    match msg {
                        NetworkMessage::GetCFCheckpt(get) => self.get_cfcheckpt(pid, get),
                        NetworkMessage::GetCFHeaders(get) => self.get_cfheaders(pid, get),
                        NetworkMessage::GetCFilters(get) => self.get_cfilters(pid, get),
                        _ => { Ok(()) }
                    }
                }
                _ => {Ok(())}
            } {
                error!("Error processing headers: {}", e);
            }
        }
        panic!("Filter server thread failed.");
    }

    fn filter_headers<'a>(&self, chaindb: &'a RwLockReadGuard<ChainDB>, filter_type: u8, start: u32, stop_hash: Sha256dHash) -> Box<Iterator<Item=Arc<StoredFilter>> + 'a> {
        if let Some(pos) = chaindb.pos_on_trunk(&stop_hash) {
            if pos >= start {
                return Box::new(chaindb.iter_trunk(start).take((pos - start + 1) as usize).filter_map(move |h| chaindb.get_block_filter_header(&h.header.bitcoin_hash(), filter_type)))
            }
        }
        Box::new(iter::empty::<Arc<StoredFilter>>())
    }

    fn get_cfcheckpt(&self, peer: PeerId, get: GetCFCheckpt) -> Result<(), MurmelError> {
        debug!("received request for filter {} checkpoints up to {} peer={}", get.filter_type, get.stop_hash, peer);
        let chaindb = self.chaindb.read().unwrap();
        let headers = self.filter_headers(&chaindb, get.filter_type, 0, get.stop_hash).enumerate()
            .filter_map(|(i, h)| if i % 1000 == 0 { Some(h.filter_id())} else { None }).collect::<Vec<_>>();
        if headers.len () > 0 {
            self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFCheckpt(
                CFCheckpt {
                    filter_type: get.filter_type,
                    stop_hash: get.stop_hash,
                    filter_headers: headers
                }
            )));
        }
        Ok(())
    }

    fn get_cfheaders(&self, peer: PeerId, get: GetCFHeaders) -> Result<(), MurmelError> {
        debug!("received request for filter {} headers {} .. {} peer={}", get.filter_type, get.start_height, get.stop_hash, peer);
        let chaindb = self.chaindb.read().unwrap();
        let filter_hashes = self.filter_headers(&chaindb, get.filter_type, get.start_height, get.stop_hash).take(2000).map(|f| f.filter_hash).collect::<Vec<_>>();
        if get.start_height == 0 {
            self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFHeaders(
                CFHeaders {
                    filter_type: get.filter_type,
                    stop_hash: get.stop_hash,
                    previous_filter: Sha256dHash::default(),
                    filter_hashes
                }
            )));
        }
        else {
            if let Some(header) = chaindb.get_header_for_height(get.start_height - 1) {
                if let Some(previous_filter) = chaindb.get_block_filter_header(&header.header.bitcoin_hash(), get.filter_type) {
                    self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFHeaders(
                        CFHeaders {
                            filter_type: get.filter_type,
                            stop_hash: get.stop_hash,
                            previous_filter: previous_filter.filter_id(),
                            filter_hashes
                        }
                    )));
                }
            }
        };

        Ok(())
    }

    fn get_cfilters(&self, peer: PeerId, get: GetCFilters) -> Result<(), MurmelError> {
        let chaindb = self.chaindb.read().unwrap();
        let filter_ids = self.filter_headers(&chaindb, get.filter_type, get.start_height, get.stop_hash).map(|f| f.filter_id()).collect::<Vec<_>>();
        for filter_id in &filter_ids {
            if let Some(filter_header) = chaindb.get_filter_header(filter_id) {
                if let Some(filter) = chaindb.fetch_filter(&filter_header.block_id, get.filter_type)? {
                    if let Some(ref content) = filter.filter {
                        self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFilter(
                            CFilter {
                                filter_type: get.filter_type,
                                block_hash: filter.block_id,
                                filter: content.clone()
                            }
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}