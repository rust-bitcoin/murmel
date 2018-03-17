//Copyright 2018 Tamas Blummer
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
use bitcoin::network::address::Address;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message::RawNetworkMessage;
use bitcoin::network::message_network::VersionMessage;
use codec::BitcoinCodec;
use futures::{future, Future, Sink, Stream};
use futures::sync::mpsc;
use node::{Node, Peer};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::net::TcpStream;
use tokio_io::AsyncRead;
use tokio::executor::current_thread;

/// Type of tehe write side of the channel to a peer
pub type Tx = mpsc::UnboundedSender<RawNetworkMessage>;

/// Connect and communicate with peers and dispatch messages to code of the local node.
pub struct Dispatcher {
    node: Rc<Node>,
    peers: Vec<SocketAddr>
}

impl Dispatcher {
    /// Create a new dispatcher for the local node
    pub fn new(node: Rc<Node>, peers: Vec<SocketAddr>) -> Dispatcher {
        Dispatcher { node: node.clone(), peers }
    }

    /// Start and connect with a known set of peers
    pub fn run(&self) -> Box<Future<Item=(), Error=()>> {
        // attempt to start clients specified by addrs (bootstrap address)
        for addr in &self.peers {
            self.start_peer(*addr);
        }
        Box::new(future::ok(()))
    }

    /// add another peer
    pub fn start_peer(&self, addr: SocketAddr) {
        current_thread::spawn(self.compile_peer_future(&addr).then(move |x| {
            trace!("client finished {:?} peer={}", x, addr);
            Ok(())
        }));
    }

    /// compile the future that dispatches to a peer
    fn compile_peer_future(&self, addr: &SocketAddr)
                           -> Box<Future<Item=(), Error=io::Error>> {
        trace!("starting peer={}", addr);

        let node = self.node.clone();

        // magic number of the network, the start of every message
        let magic = node.get_magic();

        // connect to peer
        let client = TcpStream::connect(&addr).and_then(move |socket| {
            let remote_addr = socket.peer_addr()?;
            let local_addr = socket.local_addr()?;
            trace!("connected... local: {:?}, peer {:?}", local_addr, remote_addr);
            // use the codec to split to messages
            let (sink, stream) = socket.framed(BitcoinCodec).split();
            // set up a channel that node code uses to send messages back to the peer
            let (mut tx, rx) = mpsc::unbounded();

            // first send a version message. This must be the first step for an out bound connection.
            tx.unbounded_send(Dispatcher::version_message(node.clone(), &remote_addr, &local_addr))
                .expect("tx failed");

            // handshake is perfect once we got both version and verack from peer
            let mut got_version = false;
            let mut got_verack = false;
            let tx1 = tx.clone();
            // process incoming stream
            let read = stream.for_each(move |msg: RawNetworkMessage| {
                if msg.magic != magic {
                    // stop for wrong magic
                    Err(io::Error::new(io::ErrorKind::Other, format!("message is not for this network peer={}", remote_addr)))
                } else {
                    if got_version && got_verack {
                        // regular processing
                        Ok(node.process(&msg, &remote_addr)?)
                    } else {
                        // handshake
                        let handshake = match msg.payload {
                            NetworkMessage::Version(version) => {
                                got_version = true;

                                if version.nonce == node.get_nonce() {
                                    warn!("connected to myself?");
                                    Err(io::Error::new(io::ErrorKind::Other, format!("connect to myself peer={}", remote_addr)))
                                } else {
                                    // acknowledge version message received
                                    tx1.unbounded_send(
                                        RawNetworkMessage {
                                            magic,
                                            payload: NetworkMessage::Verack,
                                        },
                                    ).unwrap();
                                    if version.services & 1 == 0 || version.version < 70001 {
                                        // want to connect to full nodes only
                                        Err(io::Error::new(io::ErrorKind::Other, format!("not a useful full node peer={}", remote_addr)))
                                    } else {
                                        // all right, remember this peer
                                        node.add_peer(
                                            &remote_addr, Peer::new(
                                                tx1.clone(),
                                                local_addr,
                                                remote_addr,
                                                version.clone(),
                                            ),
                                        );
                                        info!("Connected {} height: {} peer={}", version.user_agent, version.start_height, remote_addr);
                                        Ok(())
                                    }
                                }
                            }
                            NetworkMessage::Verack => {
                                trace!("got verack peer={}", remote_addr);
                                got_verack = true;
                                Ok(())
                            }
                            _ => {
                                trace!("misbehaving peer={}", remote_addr);
                                Err(io::Error::new(io::ErrorKind::Other, format!("misbehaving peer={}", remote_addr)))
                            }
                        };
                        if handshake.is_ok() && got_version && got_verack
                            && node.get_peer_height(&remote_addr).unwrap_or(0) > node.get_height() {
                            // if peer claims to have longer chain then ask for headers
                            Ok(node.get_headers_at_connect(&remote_addr)?)
                        } else {
                            handshake
                        }
                    }
                }
            });


            // send everything in rx to sink
            let write = sink.send_all(rx.map_err(move |()| {
                io::Error::new(io::ErrorKind::Other, format!("rx failed peer={}", remote_addr.clone()))
            }));

            let rw = write.select2(read).then (move |_| {
                Ok(info!("disconnected peer={}", remote_addr.clone()))
            });

            current_thread::spawn(rw);

            Ok(())
        });

        return Box::new(client);
    }

    pub fn version_message(node: Rc<Node>, remote: &SocketAddr, local: &SocketAddr) -> RawNetworkMessage {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        node.clone().raw_message(&NetworkMessage::Version(VersionMessage {
            version: 70001, // used only to be able to disable tx relay
            services: 0, // NODE_NONE this SPV implementation does not serve anything
            timestamp,
            receiver: Dispatcher::address_for_socket(1, remote),
            sender: Dispatcher::address_for_socket(0, local),
            nonce: node.get_nonce(),
            user_agent: "SPV".to_owned(),
            start_height: node.get_height() as i32,
            relay: false,
        }))
    }

    fn address_for_socket(services: u64, addr: &SocketAddr) -> Address {
        let (address, port) = match *addr {
            SocketAddr::V4(ref addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(ref addr) => (addr.ip().segments(), addr.port())
        };
        Address { services, address, port }
    }
}
