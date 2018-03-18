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
//! # Dispatcher from network to node and back
//!
//! This module establishes network connections and routes messages between network and node
//!

use bitcoin::network::message::RawNetworkMessage;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::constants::{Network, magic};
use bitcoin::network::address::Address;
use error::SPVError;
use futures::sync::mpsc;
use std::net::SocketAddr;
use std::sync::Arc;
use std::io;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::collections::HashMap;
use rand::{Rng, StdRng};
use tokio::executor::current_thread;
use tokio_io::AsyncRead;
use futures::{future, Future, Sink, Stream};
use tokio::net::TcpStream;
use codec::BitcoinCodec;
use node::Node;

lazy_static! {
    static ref STDRNG : Mutex<StdRng> = Mutex::new(StdRng::new().unwrap());
}

/// Type of the write side of the channel to a peer
pub type Tx = mpsc::UnboundedSender<NetworkMessage>;

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

/// The dispatcher of messages between network and node
pub struct Dispatcher {
    magic: u32,
    nonce: u64,
    height: u32
}

impl Dispatcher {

    /// create a dispatcher
    pub fn new (network: Network, height: u32) -> Dispatcher {
        Dispatcher {
            magic: magic (network),
            nonce: STDRNG.lock().unwrap().next_u64(),
            height
        }
    }

    /// Start and connect with a known set of peers
    pub fn run(&self, node: Arc<Node>, peers: Vec<SocketAddr>) -> Box<Future<Item=(), Error=()>> {
        // attempt to start clients specified by addrs (bootstrap address)
        for addr in peers {
            self.start_peer(node.clone(), addr);
        }
        Box::new(future::ok(()))
    }

    /// add another peer
    pub fn start_peer(&self, node: Arc<Node>, addr: SocketAddr) {
        current_thread::spawn(self.compile_peer_future(node, addr).then( |_| {Ok(())}));
    }

    /// compile the future that dispatches to a peer
    fn compile_peer_future(&self, node: Arc<Node>, addr: SocketAddr) -> Box<Future<Item=(), Error=io::Error>> {
        let magic = self.magic;
        let nonce = self.nonce;
        let mut height = self.height;

        let cnode = node.clone();

        let client = TcpStream::connect(&addr)
            .and_then(move |socket| {
                let remote = socket.peer_addr()?;
                let local = socket.local_addr()?;
                trace!("connected... local: {:?}, peer {:?}", &local, &remote);
                // use the codec to split to messages
                let (sink, stream) = socket.framed(BitcoinCodec).split();
                // set up a channel that node uses to send messages back to the peer
                let (tx, rx) = mpsc::unbounded();

                // first send a version message. This must be the first step for an out bound connection.
                tx.unbounded_send(Dispatcher::version(nonce, height, &remote, &local)).expect("tx should never fail");

                // handshake is perfect once we got both version and verack from peer
                let mut got_version = false;
                let mut got_verack = false;
                let mut versions = HashMap::new();

                let read = stream.for_each(move |msg: RawNetworkMessage| {
                    if msg.magic != magic {
                        return Err(io::Error::from(SPVError::Misbehaving(100, "bad magic number".to_string(), remote)));
                    }
                    if got_version && got_verack {
                        // regular processing after handshake
                        match cnode.process(&msg.payload, &remote)? {
                            ProcessResult::Ack => {},
                            ProcessResult::Height(h) => height = h,
                            ProcessResult::Ignored => trace!("ignored {} from peer={}", msg.command(), &remote),
                            ProcessResult::Disconnect =>
                                return Err(io::Error::from(SPVError::Misbehaving(100, "we hung up".to_string(), remote)))
                        }
                    }
                        else {
                            let vmsg = RawNetworkMessage { magic: msg.magic, payload: msg.payload.clone() };
                            match vmsg.payload {
                                NetworkMessage::Version(version) => {
                                    got_version = true;

                                    if version.nonce == nonce {
                                        return Err(io::Error::new(io::ErrorKind::Other, format!("connect to myself peer={}", remote)))
                                    } else {
                                        // want to connect to full nodes upporting segwit
                                        if version.services & 9 != 9 || version.version < 70001 {
                                            // want to connect to full nodes only
                                            return Err(io::Error::new(io::ErrorKind::Other, format!("not a useful peer={}", remote)))
                                        } else {
                                            // acknowledge version message received
                                            tx.unbounded_send(NetworkMessage::Verack).unwrap();
                                            // all right, remember this peer
                                            info!("Connected {} height: {} peer={}", version.user_agent, version.start_height, remote);
                                            versions.insert(remote, version);
                                        }
                                    }
                                }
                                NetworkMessage::Verack => {
                                    trace!("got verack peer={}", remote);
                                    got_verack = true;
                                }
                                _ => {
                                    trace!("misbehaving peer={}", remote);
                                    return Err(io::Error::new(io::ErrorKind::Other, format!("misbehaving peer={}", remote)))
                                }
                            };
                            if got_version && got_verack {
                                // handshake perfect
                                let version = versions.remove(&remote).unwrap();
                                match cnode.connected(version, &local,&remote, tx.clone())? {
                                    ProcessResult::Ack => {},
                                    ProcessResult::Height(h) => height = h,
                                    ProcessResult::Ignored => trace!("ignored {} from peer={}", msg.command(), &remote),
                                    ProcessResult::Disconnect =>
                                        return Err(io::Error::from(SPVError::Misbehaving(100, "we hung up".to_string(), remote)))
                                }
                            }
                        }
                    Ok(())
                });

                // send everything in rx to sink
                let write = sink.send_all(rx
                    .map(move |msg| { RawNetworkMessage { magic: magic, payload: msg }})
                    .map_err(move |()| {
                        io::Error::new(io::ErrorKind::Other, format!("rx failed peer={}", remote.clone()))
                    }));

                let wnode = node.clone();

                let rw = write.select2(read).then(move |_| {
                    info!("disconnected peer={}", remote.clone());
                    Ok(wnode.disconnected(&remote))
                });

                current_thread::spawn(rw);

                Ok(())
            });
        return Box::new(client);
    }

    /// compile a version message to be sent to new connections
    pub fn version (nonce: u64, height: u32, remote: &SocketAddr, local: &SocketAddr) -> NetworkMessage {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        NetworkMessage::Version(VersionMessage {
            version: 70001, // used only to be able to disable tx relay
            services: 0, // NODE_NONE this SPV implementation does not serve anything
            timestamp,
            receiver: Dispatcher::address_for_socket(1, remote),
            sender: Dispatcher::address_for_socket(0, local),
            nonce: nonce,
            user_agent: "SPV".to_owned(),
            start_height: height as i32,
            relay: false,
        })
    }

    /// convert socket address to Bitcoin protocol format
    fn address_for_socket(services: u64, addr: &SocketAddr) -> Address {
        let (address, port) = match *addr {
            SocketAddr::V4(ref addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(ref addr) => (addr.ip().segments(), addr.port())
        };
        Address { services, address, port }
    }
}
