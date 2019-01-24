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
    util::hash::Sha256dHash,
    network::message::NetworkMessage,
    network::message_filter::{GetCFHeaders, GetCFilters, GetCFCheckpt, CFCheckpt, CFHeaders, CFilter}
};
use chaindb::SharedChainDB;
use blockfilter::{COIN_FILTER, SCRIPT_FILTER};
use chaindb::StoredFilter;
use error::SPVError;
use p2p::{P2PControl, P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender};
use std::{
    sync::mpsc,
    thread
};

pub struct FilterServer {
    p2p: P2PControlSender,
    chaindb: SharedChainDB,
}

// channel size
const BACK_PRESSURE: usize = 10;

impl FilterServer {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(BACK_PRESSURE);

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
        panic!("Header download thread failed.");
    }

    fn filter_headers(&self, filter_type: u8, stop_hash: Sha256dHash) -> Vec<StoredFilter> {
        let chaindb = self.chaindb.read().unwrap();
        let headers = chaindb.iter_to_genesis(&stop_hash);
        let mut headers = headers.filter_map(|h| chaindb.get_block_filter(&h.header.bitcoin_hash(), filter_type)).collect::<Vec<_>> ();
        headers.reverse();
        headers
    }

    fn get_cfcheckpt(&self, peer: PeerId, get: GetCFCheckpt) -> Result<(), SPVError> {
        let headers = self.filter_headers(get.filter_type, get.stop_hash).iter().enumerate()
            .filter_map(|(i, h)| if i % 1000 == 0 { Some(h.bitcoin_hash())} else { None }).collect::<Vec<_>>();
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

    fn get_cfheaders(&self, peer: PeerId, get: GetCFHeaders) -> Result<(), SPVError> {
        let filters = self.filter_headers(get.filter_type, get.stop_hash).iter().skip(get.start_height as usize).cloned().collect::<Vec<_>>();
        let chaindb = self.chaindb.read().unwrap();
        if filters.len() > 0 && filters.len () <= 2000 {
            let previous_filter = filters.first().unwrap().previous;
            self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFHeaders(
                CFHeaders {
                    filter_type: get.filter_type,
                    stop_hash: get.stop_hash,
                    previous_filter: previous_filter,
                    filter_hashes: filters.iter().map(|f| f.filter_hash).collect::<Vec<_>>()
                }
            )));
        }
        Ok(())
    }

    fn get_cfilters(&self, peer: PeerId, get: GetCFilters) -> Result<(), SPVError> {
        let chaindb = self.chaindb.read().unwrap();
        let headers = chaindb.iter_to_genesis(&get.stop_hash);
        let mut headers = headers.filter_map(|h|
            if get.filter_type == SCRIPT_FILTER {
                Some((h.header.bitcoin_hash(), h.script_filter))
            }
            else if get.filter_type == COIN_FILTER {
                Some((h.header.bitcoin_hash(), h.coin_filter))
            }
            else {
                None
            }
        ).collect::<Vec<_>> ();
        headers.reverse();
        for (block_id, filter_pref) in headers.iter().skip(get.start_height as usize) {
            if let Some(pref) = filter_pref {
                let filter = chaindb.fetch_filter(*pref)?;
                if let Some(content) = filter.filter {
                    self.p2p.send(P2PControl::Send(peer, NetworkMessage::CFilter(
                        CFilter {
                            filter_type: get.filter_type,
                            block_hash: filter.block_id,
                            filter: content
                        }
                    )));
                }
            }
        }
        Ok(())
    }
}