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


use crate::p2p::{PeerMessageReceiver, PeerMessageSender};
use std::{
    thread,
    sync::{Arc, Mutex}
};

/// Dispatcher of incoming messages
pub struct Dispatcher<Message: Send + Sync + Clone> {
    listener: Arc<Mutex<Vec<PeerMessageSender<Message>>>>
}

impl<Message: Send + Sync + Clone + 'static> Dispatcher<Message> {
    pub fn new(incoming: PeerMessageReceiver<Message>) -> Dispatcher<Message> {
        let listener = Arc::new(Mutex::new(Vec::new()));
        let l2 = listener.clone();
        thread::Builder::new().name("dispatcher".to_string()).spawn( move || { Self::incoming_messages_loop (incoming, l2) }).unwrap();
        Dispatcher{listener}
    }

    pub fn add_listener(&mut self, listener: PeerMessageSender<Message>) {
        let mut list = self.listener.lock().unwrap();
        list.push(listener);
    }

    fn incoming_messages_loop (incoming: PeerMessageReceiver<Message>, listener: Arc<Mutex<Vec<PeerMessageSender<Message>>>>) {
        while let Ok(pm) = incoming.recv() {
            let list = listener.lock().unwrap();
            for listener in list.iter() {
                listener.send(pm.clone());
            }
        }
        panic!("dispatcher failed");
    }
}
