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
//! # regularly ping peers
//!

use bitcoin::network::message::NetworkMessage;
use crate::p2p::{
    P2PControlSender, PeerId, PeerMessage, PeerMessageReceiver, PeerMessageSender
};
use rand::{RngCore, thread_rng};
use std::{
    collections::HashMap,
    sync::mpsc,
    thread,
    time::Duration
};
use crate::timeout::{ExpectedReply, SharedTimeout};

// ping peers every SECS seconds if not asked anything else in the meanwhile
const SECS: u64 = 60;

pub struct Ping {
    p2p: P2PControlSender<NetworkMessage>,
    timeout: SharedTimeout<NetworkMessage, ExpectedReply>,
    asked: HashMap<PeerId, u64>
}


impl Ping {
    pub fn new(p2p: P2PControlSender<NetworkMessage>, timeout: SharedTimeout<NetworkMessage, ExpectedReply>) -> PeerMessageSender<NetworkMessage>  {
        let (sender, receiver) = mpsc::sync_channel(p2p.back_pressure);
        let mut ping = Ping { p2p, timeout, asked: HashMap::new() };

        thread::Builder::new().name("ping".to_string()).spawn(move || { ping.run(receiver) }).unwrap();

        PeerMessageSender::new(sender)
    }

    fn run(&mut self, receiver: PeerMessageReceiver<NetworkMessage>) {
        loop {
            while let Ok(msg) = receiver.recv_timeout(Duration::from_millis(SECS*1000)) {
                match msg {
                    PeerMessage::Disconnected(pid,_) => {
                        self.timeout.lock().unwrap().forget(pid);
                        self.asked.remove(&pid);
                    },
                    PeerMessage::Incoming(pid, msg) => {
                        match msg {
                            NetworkMessage::Pong(n) => {
                                if self.asked.remove(&pid) == Some(n) {
                                    self.timeout.lock().unwrap().received(pid, 1, ExpectedReply::Pong);
                                }
                            }
                            _ => { }
                        }
                    }
                    _ => {}
                }
            }
            self.timeout.lock().unwrap().check(vec!(ExpectedReply::Pong));
            for peer in self.p2p.peers() {
                if !self.timeout.lock().unwrap().is_busy(peer) {
                    let ask = thread_rng().next_u64();
                    self.asked.insert(peer, ask);
                    self.timeout.lock().unwrap().expect(peer, 1, ExpectedReply::Pong);
                    self.p2p.send_network(peer, NetworkMessage::Ping(ask));
                }
            }
        }
    }
}