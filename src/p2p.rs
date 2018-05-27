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
//! This module establishes network connections and routes messages between the P2P network and this node
//!

use bitcoin::network::constants::{magic, Network};
use bitcoin::network::encodable::{ConsensusDecodable, ConsensusEncodable};
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message::RawNetworkMessage;
use bitcoin::network::message_network::VersionMessage;
use bitcoin::network::serialize::{RawDecoder, RawEncoder};
use bitcoin::network::address::Address;
use bitcoin::util;
use bytes::{BufMut, BytesMut};
use error::SPVError;
use mio::*;
use mio::unix::UnixReady;
use mio::net::TcpStream;
use node::{Node, ProcessResult};
use rand::{Rng, StdRng};
use std::cmp::{max, min};
use std::collections::HashMap;
use std::fmt::{Display, Error, Formatter};
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, mpsc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MESSAGE_SIZE :usize = 4*1024*1024;

/// Type of a peer's Id
#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct PeerId {
    /// mio token used in networking
    pub token: Token
}

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{}", self.token.0)?;
        Ok(())
    }
}

/// The dispatcher of messages between network and node
pub struct P2P {
    magic: u32,
    nonce: u64,
    height: u32,
    user_agent: String,
    peers: RwLock<HashMap<PeerId, Peer>>,
    poll: Arc<Poll>
}

impl P2P {
    /// create a dispatcher
    pub fn new(user_agent: String, network: Network, height: u32) -> P2P {
        let mut rng = StdRng::new().unwrap();
        P2P {
            magic: magic(network),
            nonce: rng.next_u64(),
            height,
            user_agent,
            peers: RwLock::new(HashMap::new()),
            poll: Arc::new(Poll::new().unwrap())
        }
    }

    /// Add a peer
    pub fn add_peer (&self, addr: &SocketAddr) -> Result<PeerId, SPVError> {
        let token = Token(self.peers.read().unwrap().len());
        let pid = PeerId{token};
        info!("initiating connect to {} peer={}", addr, pid);
        let peer = Peer::new(pid, token, self.poll.clone(), addr, self.nonce)?;
        // need to lock before send as send will trigger lookup in peers
        let mut peers = self.peers.write().unwrap();
        peer.send(&P2P::version(&self.user_agent, self.nonce, self.height, addr))?;
        peers.insert(pid, peer);
        Ok(pid)
    }

    fn version (user_agent: &String, nonce: u64, height: u32, remote: &SocketAddr) -> NetworkMessage {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        NetworkMessage::Version(VersionMessage {
            version: 70001, // used only to be able to disable tx relay
            services: 0, // NODE_NONE this SPV implementation does not serve anything
            timestamp,
            receiver: Address::new(remote, 1),
            sender: Address::new(remote, 0), // TODO set this to local
            nonce: nonce,
            user_agent: user_agent.clone(),
            start_height: height as i32,
            relay: false,
        })
    }

    /// Send a message to a peer
    pub fn send (&self, pid: PeerId, msg: &NetworkMessage) -> Result<(), SPVError> {
        if let Some(peer) = self.peers.read().unwrap().get (&pid) {
            peer.send(msg)
        } else {
            Ok(())
        }
    }

    /// Send a message to all peers
    pub fn broadcast (&self, msg: &NetworkMessage) -> Result<(), SPVError> {
        for peer in self.peers.read().unwrap().values() {
            peer.send(msg)?;
        }
        Ok(())
    }

    /// run the dispatcher loop
    /// // this method does not return unless there is a serious networking error
    pub fn run(&self, node: Arc<Node>) -> Result<(), SPVError> {
        let mut events = Events::with_capacity(1024);
        trace!("start mio event loop");
        loop {
            self.poll.poll(&mut events, None)?;

            for event in events.iter() {
                let pid = PeerId { token: event.token() };

                if event.readiness().contains(Ready::hup()) {
                    // node.disconnected(pid)?; TODO
                    self.peers.write().unwrap().remove(&pid);
                    info!("left us peer={}", pid);
                } else if let Some(peer) = self.peers.write().unwrap().get_mut(&pid) {
                    if event.readiness().contains(Ready::readable()) {
                        let mut buffer = [0u8; MAX_MESSAGE_SIZE];
                        while let Ok(len) = peer.stream.read(&mut buffer) {
                            if len == 0 {
                                break;
                            }
                            peer.buffer.extend_from_slice(&buffer[0..len]);
                            while let Some(msg) = decode (&mut peer.buffer)? {
                                trace!("received {} peer={}", msg.command(), pid);
                                match peer.process_incoming (&msg, node.clone())? {
                                    ProcessResult::Disconnect => {
                                        self.peers.write().unwrap().remove(&pid);
                                        info!("disconnected peer={}", pid);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    if event.readiness().contains(Ready::writable()) {
                        while let Some(msg) = peer.try_receive () {
                            let mut buffer = BytesMut::with_capacity(MAX_MESSAGE_SIZE);
                            let raw = RawNetworkMessage { magic: self.magic, payload: msg };
                            encode ( &raw, &mut buffer)?;
                            peer.stream.write(buffer.as_ref())?;
                            trace!("sent {} to peer={}", raw.command(), pid);
                        }
                        peer.deregister()?;
                        peer.register_read()?;
                    }
                }
            }
        }
    }
}

/// a peer
pub struct Peer {
    /// the peer's id for log messages
    pub pid: PeerId,
    poll: Arc<Poll>,
    stream: TcpStream,
    buffer: BytesMut,
    got_verack: bool,
    nonce: u64,
    /// the version message the peer sent to us at connect
    pub version: Option<VersionMessage>,
    sender: mpsc::Sender<NetworkMessage>,
    receiver: mpsc::Receiver<NetworkMessage>
}

impl Peer {
    /// create a new peer
    pub fn new (pid: PeerId, token: Token, poll: Arc<Poll>, addr: &SocketAddr, nonce: u64) -> Result<Peer, SPVError> {

        let stream = TcpStream::connect(addr)?;
        let (sender, receiver) = mpsc::channel();
        let peer = Peer{pid, poll: poll.clone(), stream, buffer: BytesMut::new(),
            got_verack: false, nonce, version: None, sender, receiver};
        peer.register_read()?;
        Ok(peer)
    }

    fn register_read (&self) -> Result<(), SPVError> {
        trace!("register for mio read peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::readable()|UnixReady::error(), PollOpt::edge())?;
        Ok(())
    }

    /// send a message to P2P network
    pub fn send (&self, msg: &NetworkMessage) -> Result<(), SPVError> {
        self.sender.send(msg.clone()).map_err(| _ | SPVError::Generic("can not send to peer queue".to_owned()))?;
        trace!("de-register mio events peer={}", self.pid);
        self.deregister()?;
        self.register_write()?;
        Ok(())
    }

    fn deregister (&self) -> Result<(), SPVError> {
        self.poll.deregister(&self.stream)?;
        Ok(())
    }

    fn register_write (&self) -> Result<(), SPVError> {
        trace!("register for mio write peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::writable()|UnixReady::error(), PollOpt::edge())?;
        Ok(())
    }

    /// try to receive a message from node
    pub fn try_receive (&self) -> Option<NetworkMessage> {
        if let Ok (msg) = self.receiver.try_recv() {
            Some (msg)
        } else {
            None
        }
    }

    fn process_incoming (&mut self, msg: &RawNetworkMessage, node: Arc<Node>) -> Result<ProcessResult, SPVError> {
        if self.version.is_some() && self.got_verack {
            // after handshake
            match node.process (&msg.payload, self)? {
                ProcessResult::Ack | ProcessResult::Ignored => {},
                ProcessResult::Disconnect => {
                    self.stream.shutdown(Shutdown::Both)?;
                    return Ok(ProcessResult::Disconnect)
                },
                ProcessResult::Height(new_height) => {
                    let mut nv = self.version.clone().unwrap();
                    nv.start_height = new_height as i32;
                    self.version = Some(nv);
                }
            }
        }
        else {
            // before handshake complete
            match msg.payload {
                NetworkMessage::Version(ref version) => {
                    if self.version.is_some() {
                        return Err(SPVError::Misbehaving(100, "misbehaving: repeated version".to_owned()));
                    }

                    if version.nonce == self.nonce {
                        return Err(SPVError::Misbehaving(100, "connect to myself".to_owned()));
                    } else {
                        // want to connect to full nodes upporting segwit
                        if version.services & 9 != 9 || version.version < 70013 {
                            return Err(SPVError::Generic("not a useful peer".to_owned()));
                        } else {
                            // acknowledge version message received
                            self.send(&NetworkMessage::Verack)?;
                            // all right, remember this peer
                            info!("Connected {} height: {} peer={}", version.user_agent, version.start_height, self.pid);
                            self.version = Some(version.clone());
                        }
                    }
                }
                NetworkMessage::Verack => {
                    if self.got_verack {
                        return Err(SPVError::Misbehaving(100, "misbehaving: repeated verack".to_owned()));
                    }
                    trace!("got verack peer={}", self.pid);
                    self.got_verack = true;
                }
                _ => {
                    trace!("misbehaving peer={}", self.pid);
                    return Err(SPVError::Misbehaving(100, "misbehaving: handshake".to_owned()));
                }
            };
            if self.version.is_some() && self.got_verack {
                // handshake perfect
                info!("connected peer={}", self.pid);
                node.connected(self)?;
            }
        }
        return Ok(ProcessResult::Ack)
    }
}

/// A helper class that wrap BytesMut so it implements io::Read and io::Write
struct BufferRW<'a> (&'a mut BytesMut);

impl<'a> io::Write for BufferRW<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if self.0.remaining_mut() < buf.len() {
            self.0.reserve(max(1024, buf.len()));
        }
        self.0.put_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl<'a> io::Read for BufferRW<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let minlen = min(self.0.len(), buf.len());
        buf[..minlen].copy_from_slice(&self.0.split_to(minlen));
        Ok(minlen)
    }
}

fn encode(item: &RawNetworkMessage, dst: &mut BytesMut) -> Result<(), io::Error> {
    match item.consensus_encode(&mut RawEncoder::new(BufferRW(dst))) {
        Ok(_) => Ok(()),
        Err(e) => Err(io::Error::new(io::ErrorKind::WriteZero, e))
    }
}

fn decode(src: &mut BytesMut) -> Result<Option<RawNetworkMessage>, io::Error> {
    // TODO: this is a wasteful solution
    // all I'd need is reset src position if decode fails with ByteOrder
    // could however not find a BytesMut API to do so
    let mut buf = src.clone();
    let decode: Result<RawNetworkMessage, util::Error> =
        ConsensusDecodable::consensus_decode(&mut RawDecoder::new(BufferRW(&mut buf)));
    match decode {
        Ok(m) => {
            let sl = src.len();
            src.advance(sl - buf.len());
            Ok(Some(m))
        }
        Err(util::Error::ByteOrder(_)) => Ok(None),
        Err(e) => {
            trace!("invalid data in codec: {} size {}", e, src.len());
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}
