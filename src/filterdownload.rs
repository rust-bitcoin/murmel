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
//! # Download block filters
//!

use bitcoin::{
    BitcoinHash,
    network::{
        message::NetworkMessage,
        message_blockdata::{Inventory, InvType},
        message_filter::{
            CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders
        },
    },
    util::hash::Sha256dHash
};
use blockfilter::{COIN_FILTER, SCRIPT_FILTER};
use chaindb::SharedChainDB;
use chaindb::StoredFilter;
use error::MurmelError;
use p2p::{P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender, SERVICE_FILTERS};
use std::{
    sync::mpsc,
    thread,
    time::Duration,
};
use timeout::{ExpectedReply, SharedTimeout};

pub struct FilterDownload {
    p2p: P2PControlSender,
    chaindb: SharedChainDB,
    timeout: SharedTimeout,
}

impl FilterDownload {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender, timeout: SharedTimeout) -> PeerMessageSender {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut filterdownload = FilterDownload { chaindb, p2p, timeout };

        thread::spawn(move || { filterdownload.run(receiver) });

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                if let Err(e) = match msg {
                    PeerMessage::Connected(pid) => {
                        if self.is_serving_filters(pid) {
                            self.get_filter_checkpoints(pid, SCRIPT_FILTER)
                        } else {
                            Ok(())
                        }
                    }
                    PeerMessage::Disconnected(_) => {
                        Ok(())
                    }
                    PeerMessage::Message(pid, msg) => {
                        if self.is_serving_filters(pid) {
                            match msg {
                                NetworkMessage::Ping(_) => self.get_filter_headers(pid, SCRIPT_FILTER),
                                NetworkMessage::CFHeaders(headers) => self.filter_headers(headers, pid),
                                NetworkMessage::CFilter(filter) => self.filter(filter, pid),
                                NetworkMessage::CFCheckpt(c) => self.checkpoint(c, pid),
                                NetworkMessage::Inv(inv) => self.inv(inv, pid),
                                _ => { Ok(()) }
                            }
                        }
                        else {
                            Ok(())
                        }
                    }
                } {
                    error!("Error processing filters: {}", e);
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::FilterHeader, ExpectedReply::FilterCheckpoints));
        }
    }

    fn is_serving_filters (&self, peer: PeerId) -> bool {
        if let Some(peer_version) = self.p2p.peer_version(peer) {
            return peer_version.services & SERVICE_FILTERS != 0;
        }
        false
    }

    fn get_filter_checkpoints(&mut self, peer: PeerId, filter_type: u8) -> Result<(), MurmelError> {
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::FilterCheckpoints) {
            return Ok(());
        }
        if let Some(tip) = self.chaindb.read().unwrap().header_tip() {
            self.p2p.send_network(peer, NetworkMessage::GetCFCheckpt(GetCFCheckpt { filter_type, stop_hash: tip.header.bitcoin_hash() }));
            self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::FilterCheckpoints);
        }
        Ok(())
    }

    fn checkpoint (&mut self, checkpoints: CFCheckpt, peer: PeerId) -> Result<(), MurmelError> {
        let mut ok = true;
        {
            self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::FilterCheckpoints);
            let chaindb = self.chaindb.read().unwrap();
            for header in chaindb.iter_trunk(0) {
                if header.height as usize == checkpoints.filter_headers.len() {
                    break;
                }
                if header.height % 1000 == 0 {
                    if let Some(filter) = chaindb.get_block_filter_header(&header.header.bitcoin_hash(), checkpoints.filter_type) {
                        if filter.filter_id() != checkpoints.filter_headers[header.height as usize / 1000] {
                            debug!("filter {} checkpoint mismatch at height {} with peer={}", checkpoints.filter_type, header.height, peer);
                            ok = false;
                        }
                    }
                }
            }
            debug!("filter {} checkpoints match with peer={}", checkpoints.filter_type, peer);
        }
        if ok {
            self.get_filter_headers(peer, checkpoints.filter_type)?;
        }
        Ok(())
    }

    fn get_filter_headers(&mut self, peer: PeerId, filter_type: u8) -> Result<(), MurmelError> {
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::FilterHeader) {
            return Ok(());
        }
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::FilterCheckpoints) {
            return Ok(());
        }
        let chaindb = self.chaindb.read().unwrap();
        if let Some(tip) = chaindb.header_tip() {
            let mut start_height = 0;
            let mut stop_hash = tip.bitcoin_hash();
            for header in chaindb.iter_trunk_rev(None) {
                if chaindb.get_block_filter_header(&header.header.bitcoin_hash(), filter_type).is_some () {
                    start_height = header.height + 1;
                    break;
                }
            }
            if start_height <= tip.height {
                for (i, sh) in chaindb.iter_trunk(start_height).enumerate() {
                    if i == 2000 {
                        break;
                    }
                    stop_hash = sh.header.bitcoin_hash();
                }
                self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::FilterHeader);
                debug!("asking for {} filter headers start height {} stop block {} peer={}", if filter_type == SCRIPT_FILTER { "script" } else { "coin" }, start_height, stop_hash, peer);
                self.p2p.send_network(peer, NetworkMessage::GetCFHeaders(GetCFHeaders { filter_type: SCRIPT_FILTER, start_height, stop_hash }));
            }
        }
        Ok(())
    }

    fn filter_headers(&mut self, headers: CFHeaders, peer: PeerId) -> Result<(), MurmelError> {
        let next_block_pos = if headers.previous_filter == Sha256dHash::default() {
            Some(0)
        }
        else {
            let chaindb = self.chaindb.read().unwrap();
            if let Some(filter) = chaindb.get_filter_header(&headers.previous_filter) {
                if let Some(pos) = chaindb.pos_on_trunk(&filter.block_id) {
                    Some(pos+1)
                }
                else {
                    None
                }
            }
            else {
                debug!("unknown previous filter {} peer={}", headers.previous_filter, peer);
                None
            }
        };
        let mut stored = 0;
        if let Some(trunk_pos) = next_block_pos {
            self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::FilterHeader);

            let mut chaindb = self.chaindb.write().unwrap();
            let mut previous = headers.previous_filter;
            let id_pairs = chaindb.iter_trunk(trunk_pos).map(|h|h.header.bitcoin_hash()).zip(headers.filter_hashes.iter().cloned()).collect::<Vec<_>>();
            for (block_id, filter_hash) in  id_pairs {

                let filter = StoredFilter { block_id, previous, filter_hash, filter: None, filter_type: headers.filter_type };
                previous = filter.filter_id();

                if chaindb.get_filter_header(&filter.filter_id()).is_none() {
                    stored += 1;
                    chaindb.add_filter(filter)?;
                }

            }
        }
        if stored > 0 {
            debug!("stored {} filters peer={}", stored, peer);
            self.get_filter_headers(peer, headers.filter_type)?;
        }
        Ok(())
    }

    fn filter (&mut self, filter: CFilter, peer: PeerId) -> Result<(), MurmelError> {
        Ok(())
    }

    fn inv(&mut self, v: Vec<Inventory>, peer: PeerId) -> Result<(), MurmelError> {
        let mut ask_for_headers = false;
        for inventory in v {
            // only care for blocks
            if inventory.inv_type == InvType::Block {
                let chaindb = self.chaindb.read().unwrap();
                debug!("received inv for block {}", inventory.hash);
                if chaindb.get_block_filter_header(&inventory.hash, SCRIPT_FILTER).is_none() {
                    // ask for filter headers if observing a new block
                    ask_for_headers = true;
                    break;
                }
                if chaindb.get_block_filter_header(&inventory.hash, COIN_FILTER).is_none() {
                    // ask for filter headers if observing a new block
                    ask_for_headers = true;
                    break;
                }
            }
        }
        if ask_for_headers {
            self.get_filter_headers(peer, SCRIPT_FILTER)?;
            self.get_filter_headers(peer, COIN_FILTER)?;
        }
        Ok(())
    }
}