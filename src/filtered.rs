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
    blockdata::block::Block,
    network::{
        message::NetworkMessage,
        message_blockdata::{Inventory, InvType},
        message_filter::{
            CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters
        },
    },
    util::bip158::BlockFilterReader
};

use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;

use chaindb::SharedChainDB;
use chaindb::StoredFilter;
use error::Error;
use p2p::{P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender, SERVICE_FILTERS};
use std::{
    sync::mpsc,
    thread,
    time::Duration,
    io::Cursor
};
use timeout::{ExpectedReply, SharedTimeout};
use downstream::SharedDownstream;

pub struct Filtered {
    p2p: P2PControlSender<NetworkMessage>,
    chaindb: SharedChainDB,
    timeout: SharedTimeout<NetworkMessage, ExpectedReply>,
    birth_height: Option<u32>,
    #[allow(unused)] // TODO send blocks
    downstream: SharedDownstream
}

impl Filtered {
    pub fn new(chaindb: SharedChainDB, p2p: P2PControlSender<NetworkMessage>, timeout: SharedTimeout<NetworkMessage, ExpectedReply>, downstream: SharedDownstream, birth_height: Option<u32>) -> PeerMessageSender<NetworkMessage> {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);

        let mut filterdownload = Filtered { chaindb, p2p, timeout, downstream, birth_height };

        thread::Builder::new().name("filter download".to_string()).spawn(move || { filterdownload.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(1000)) {
                if let Err(e) = match msg {
                    PeerMessage::Connected(pid,_) => {
                        if self.is_serving_filters(pid) {
                            self.get_filter_checkpoints(pid, 0)
                        } else {
                            Ok(())
                        }
                    }
                    PeerMessage::Disconnected(_, _) => {
                        Ok(())
                    }
                    PeerMessage::Incoming(pid, msg) => {
                        if self.is_serving_filters(pid) {
                            match msg {
                                NetworkMessage::Ping(_) => self.get_filter_headers(pid, 0),
                                NetworkMessage::CFHeaders(headers) => self.filter_headers(headers, pid),
                                NetworkMessage::CFilter(filter) => self.filter(filter, pid),
                                NetworkMessage::CFCheckpt(c) => self.checkpoint(c, pid),
                                NetworkMessage::Inv(inv) => self.inv(inv, pid),
                                NetworkMessage::Block(block) => self.block(block, pid),
                                _ => { Ok(()) }
                            }
                        }
                        else {
                            Ok(())
                        }
                    },
                    _ => { Ok(())}
                } {
                    error!("Error processing filters: {}", e);
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::FilterHeader, ExpectedReply::FilterCheckpoints, ExpectedReply::Block, ExpectedReply::Filter));
        }
    }

    fn is_serving_filters (&self, peer: PeerId) -> bool {
        if let Some(peer_version) = self.p2p.peer_version(peer) {
            return peer_version.services & SERVICE_FILTERS != 0;
        }
        false
    }

    fn get_filter_checkpoints(&mut self, peer: PeerId, filter_type: u8) -> Result<(), Error> {
        if self.timeout.lock().unwrap().is_busy_with(peer, ExpectedReply::FilterCheckpoints) {
            return Ok(());
        }
        if let Some(tip) = self.chaindb.read().unwrap().header_tip() {
            self.p2p.send_network(peer, NetworkMessage::GetCFCheckpt(GetCFCheckpt { filter_type, stop_hash: tip.bitcoin_hash() }));
            self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::FilterCheckpoints);
        }
        Ok(())
    }

    fn checkpoint (&mut self, checkpoints: CFCheckpt, peer: PeerId) -> Result<(), Error> {
        let mut ok = true;
        {
            self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::FilterCheckpoints);
            let chaindb = self.chaindb.read().unwrap();
            for header in chaindb.iter_trunk(0) {
                if header.stored.height as usize == checkpoints.filter_headers.len() {
                    break;
                }
                if header.stored.height % 1000 == 0 {
                    if let Some(filter_header) = chaindb.get_block_filter(&header.bitcoin_hash(), checkpoints.filter_type) {
                        if filter_header.filter_id() != checkpoints.filter_headers[header.stored.height as usize / 1000] {
                            debug!("filter {} checkpoint mismatch at height {} with peer={}", checkpoints.filter_type, header.stored.height, peer);
                            ok = false;
                            if chaindb.fetch_stored_block(&header.bitcoin_hash())?.is_some() {
                                // we accepted a block previously that matches this filter. This peer must be lying.
                                debug!("go checkpoint contradicting checked block, banning peer={}", peer);
                                self.p2p.ban(peer, 100);
                            }
                            else {
                                // we do not yet know the filter, get it to decide
                                self.p2p.send_network(peer, NetworkMessage::GetCFilters(
                                    GetCFilters{filter_type: checkpoints.filter_type, start_height: header.stored.height, stop_hash: header.bitcoin_hash()}
                                ));
                                self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::Filter);
                            }
                            break;
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

    fn block(&mut self, block: Block, peer: PeerId) -> Result<(), Error> {
        // do not store fake blocks
        if block.check_merkle_root() && block.check_witness_commitment() {
            let mut chaindb = self.chaindb.write().unwrap();
            // have to have filter stored before
            if let Some(filter) = chaindb.fetch_block_filter(&block.bitcoin_hash(), 0)? {
                if let Some(content) = filter.filter {
                    self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::Block);
                    let mut query = Vec::new();
                    for transaction in &block.txdata {
                        for output in &transaction.output {
                            if !output.script_pubkey.is_op_return() {
                                query.push(output.script_pubkey.as_bytes());
                            }
                        }
                    }
                    let filter_reader = BlockFilterReader::new(&block.bitcoin_hash());
                    if filter_reader.match_all(&mut Cursor::new(content), &mut query.iter().cloned())? == false {
                        debug!("block {} does not match previous filter assumption peer={}", block.bitcoin_hash(), peer);
                        // TODO this gets messy: forget previously stored filter chain
                    } else {
                        // everything checks out, store
                        chaindb.store_block(&block)?;
                        chaindb.batch()?;
                    }
                }
            }
        }
        Ok(())
    }

    fn get_filter_headers(&mut self, peer: PeerId, filter_type: u8) -> Result<(), Error> {
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
                if chaindb.get_block_filter(&header.bitcoin_hash(), filter_type).is_some () {
                    start_height = header.stored.height + 1;
                    break;
                }
            }
            if start_height <= tip.stored.height {
                for (i, sh) in chaindb.iter_trunk(start_height).enumerate() {
                    if i == 2000 {
                        break;
                    }
                    stop_hash = sh.bitcoin_hash();
                }
                self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::FilterHeader);
                debug!("asking for {} filter headers start height {} stop block {} peer={}", if filter_type == 0 { "script" } else { "coin" }, start_height, stop_hash, peer);
                self.p2p.send_network(peer, NetworkMessage::GetCFHeaders(GetCFHeaders { filter_type: 0, start_height, stop_hash }));
            }
        }
        Ok(())
    }

    fn filter_headers(&mut self, headers: CFHeaders, peer: PeerId) -> Result<(), Error> {
        let next_block_pos = if headers.previous_filter == Sha256dHash::default() {
            Some(0)
        }
        else {
            let chaindb = self.chaindb.read().unwrap();
            if let Some(filter) = chaindb.get_filter(&headers.previous_filter) {
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
            let mut ask_filters = Vec::new();
            let mut previous = headers.previous_filter;
            let id_pairs = chaindb.iter_trunk(trunk_pos).cloned().zip(headers.filter_hashes.iter().cloned()).collect::<Vec<_>>();
            for (header, filter_hash) in  id_pairs {

                let filter = StoredFilter { block_id: header.bitcoin_hash(), previous, filter_hash, filter: None, filter_type: headers.filter_type };
                previous = filter.filter_id();

                if chaindb.get_filter(&filter.filter_id()).is_none() {
                    stored += 1;
                    chaindb.add_filter(filter)?;
                    if let Some(birth_height) = self.birth_height {
                        if birth_height <= header.stored.height {
                            ask_filters.push(header);
                        }
                    }
                }
            }
            if !ask_filters.is_empty() {
                let start_height = ask_filters[0].stored.height;
                let stop_hash = ask_filters.last().unwrap().bitcoin_hash();
                self.timeout.lock().unwrap().expect(peer, ask_filters.len(), ExpectedReply::Filter);
                self.p2p.send_network(peer, NetworkMessage::GetCFilters(GetCFilters{filter_type: headers.filter_type, start_height, stop_hash}));
            }
        }
        if stored > 0 {
            debug!("stored {} filters peer={}", stored, peer);
            self.get_filter_headers(peer, headers.filter_type)?;
        }
        Ok(())
    }

    fn filter (&mut self, filter: CFilter, peer: PeerId) -> Result<(), Error> {
        let mut chaindb = self.chaindb.write().unwrap();
        if let Some(filter_header) = chaindb.get_block_filter(&filter.block_hash, filter.filter_type) {
            self.timeout.lock().unwrap().received(peer, 1, ExpectedReply::Filter);

            let filter_hash = Sha256dHash::hash(filter.filter.as_slice());

            if filter_header.filter_hash == filter_hash {
                // checks out with previously downloaded header, just store
                let mut stored_filter = (*filter_header).clone();
                stored_filter.filter = Some(filter.filter);
                chaindb.add_filter_header(stored_filter)?;

                // TODO match here to decide if we need the block need ling to lightning's watches
            }
            else {
                // Does not check out with previously stored header, get the block
                self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::Block);
                debug!("asking for block {} to verify checkpoint of peer={}", filter.block_hash, peer);
                self.p2p.send_network(peer, NetworkMessage::GetData(vec!(Inventory{inv_type: InvType::Block, hash: filter.block_hash})));
            }
        }
        Ok(())
    }

    fn inv(&mut self, v: Vec<Inventory>, peer: PeerId) -> Result<(), Error> {
        let mut ask_for_headers = false;
        for inventory in v {
            // only care for blocks
            if inventory.inv_type == InvType::Block {
                let chaindb = self.chaindb.read().unwrap();
                debug!("received inv for block {}", inventory.hash);
                if chaindb.get_block_filter(&inventory.hash, 0).is_none() {
                    // ask for filter headers if observing a new block
                    ask_for_headers = true;
                    break;
                }
            }
        }
        if ask_for_headers {
            self.get_filter_headers(peer, 0)?;
        }
        Ok(())
    }
}