//
// Copyright 2018-19 Tamas Blummer
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
//! # Calculate filter
//!

use chaindb::SharedChainDB;

use p2p::{PeerMessageReceiver, PeerMessageSender};

use std::{
    thread,
    sync::{Arc, mpsc}
};

pub struct FilterCalculator {
    chaindb: SharedChainDB
}

impl FilterCalculator {
    pub fn new (chaindb: SharedChainDB) -> PeerMessageSender {
        let (sender, receiver) = mpsc::channel();

        let mut calculator = FilterCalculator { chaindb };
        thread::spawn(move || calculator.run(receiver));
        PeerMessageSender::new(sender)
    }

    fn run(&mut self, work: PeerMessageReceiver) {
    }
}