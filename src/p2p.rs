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
use error::SPVError;
use mio::*;
use mio::unix::UnixReady;
use mio::net::TcpStream;
use node::{Node, ProcessResult};
use database::DB;
use rand::{Rng, StdRng};
use std::cmp::{min, max};
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Entry;
use std::fmt::{Display, Error, Formatter};
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, mpsc, RwLock, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering,AtomicBool};
use std::time::{SystemTime, UNIX_EPOCH};
use std::cell::Cell;
use futures::{Future, Async, FutureExt};
use futures::future;
use futures::task::{Context, Waker};
use std::time::Duration;
use futures_timer::Delay;

const IO_BUFFER_SIZE:usize = 1024*1024;
const EVENT_BUFFER_SIZE:usize = 1024;
const CONNECT_TIMEOUT_SECONDS: u64 = 5;
const BAN :u32 = 100;

/// A peer's Id
/// used in log messages and as key to PeerMap
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

/// a map of peer id to peers
/// This map is shared between P2P and node
/// and is protected with an rw lock
/// Peers are mutex protected as sends
/// to them may be coming from different peers
pub type PeerMap = HashMap<PeerId, Mutex<Peer>>;

/// The P2P network layer
pub struct P2P {
    // network specific message prefix
    magic: u32,
    // This node's identifier on the network (random)
    nonce: u64,
    // height of the blockchain tree trunk
    height: u32,
    // This node's human readable type identification
    user_agent: String,
    // The collection of connected peers
    // access to this is shared with node and is rw lock protected
    peers: Arc<RwLock<PeerMap>>,
    // The poll object of the async IO layer (mio)
    // access to this is shared by P2P and Peer
    poll: Arc<Poll>,
    // next peer id
    // atomic only for interior mutability
    next_peer_id: AtomicUsize,
    // database
    db: Arc<Mutex<DB>>
}

impl P2P {
    /// create a new P2P network controller
    pub fn new(user_agent: String, network: Network, height: u32, peers: Arc<RwLock<PeerMap>>, db: Arc<Mutex<DB>>) -> P2P {
        let mut rng = StdRng::new().unwrap();
        P2P {
            magic: magic(network),
            nonce: rng.next_u64(),
            height,
            user_agent,
            peers,
            poll: Arc::new(Poll::new().unwrap()),
            next_peer_id: AtomicUsize::new(0),
            db
        }
    }

    /// return a future that does not complete until the peer is connected
    pub fn add_peer (&self, addr: &SocketAddr) -> Box<Future<Item=SocketAddr, Error=SPVError> + Send> {
        let connect = self.connect_peer_with_timeout(addr, CONNECT_TIMEOUT_SECONDS);

        let peers = self.peers.clone();
        let address = addr.clone();

        Box::new(connect.and_then (move|pid| {
            Box::new(future::poll_fn (move | ctx | {
                // retrieve peer from peer map
                if let Some(peer) = peers.read().unwrap().get(&pid) {
                    // return pid if peer is connected (handshake perfect)
                    let mut locked_peer = peer.lock().unwrap();
                    // store waker of this task to peer
                    // wakeup with this will trigger a new poll
                    locked_peer.disconnected_waker = Some(ctx.waker().clone());
                    Ok(Async::Pending)
                } else {
                    Ok(Async::Ready(address))
                }
            }
            ))}))
    }

    /// return a future that resolves to a connected (handshake perfect) peer or timeout
    pub fn connect_peer_with_timeout (&self, addr: &SocketAddr, seconds: u64) -> Box<Future<Item=PeerId, Error=SPVError> + Send> {
        use futures_timer::FutureExt;

        Box::new(self.connect_peer(addr).timeout(Duration::from_secs(seconds)))
    }

    // connect a peer
    fn connect_peer(&self, addr: &SocketAddr) -> Box<Future<Item=PeerId, Error=SPVError> + Send> {
        let peers = self.peers.clone();
        let socket_address = addr.clone();

        // initiate connection
        match self.initiate_connect(addr) {
            // connection initiated, resolve to a future that polls for handshake complete
            Ok(pid) => Box::new(
                future::poll_fn (move |ctx|
                    {
                        // retrieve peer from peer map
                        if let Some(peer) = peers.read().unwrap().get(&pid) {
                            // return pid if peer is connected (handshake perfect)
                            let mut locked_peer = peer.lock().unwrap();
                            if locked_peer.connected.get() {
                                locked_peer.connected_waker = None;
                                Ok(Async::Ready(pid))
                            } else {
                                // store waker of this task to peer
                                // wakeup with this will trigger a new poll
                                locked_peer.connected_waker = Some(ctx.waker().clone());
                                Ok(Async::Pending)
                            }
                        } else {
                            Err(SPVError::UnknownPeer(socket_address))
                        }
                    })),
            // resolve to an error returning future if initiation fails
            Err(e) => Box::new(future::err(e))
        }
    }

    // initiate connect to peer
    fn initiate_connect(&self, addr: &SocketAddr) -> Result<PeerId, SPVError> {
        // new token, never re-using previously connected peer's id
        // so log messages are easier to follow
        let token = Token(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        let pid = PeerId{token};

        info!("initiating connect to {} peer={}", addr, pid);

        // create lock protected peer object
        let peer = Mutex::new(Peer::new(pid, self.poll.clone(), addr, self.nonce)?);

        // add peer object to peer map shared between P2P and node
        let mut peers = self.peers.write().unwrap();

        // send this node's version message to peer
        peer.lock().unwrap().send(&P2P::version(&self.user_agent, self.nonce, self.height, addr))?;

        // add to peer map
        peers.insert(pid, peer);

        trace!("added peer={}", pid);
        Ok(pid)
    }

    // compile this node's version message
    fn version (user_agent: &String, nonce: u64, height: u32, remote: &SocketAddr) -> NetworkMessage {
        // now in unix time
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        // build message
        NetworkMessage::Version(VersionMessage {
            version: 70001, // used only to be able to disable tx relay
            services: 0, // NODE_NONE this SPV implementation does not serve anything
            timestamp,
            receiver: Address::new(remote, 1),
            // TODO: sender is only dummy
            sender: Address::new(remote, 1),
            nonce: nonce,
            user_agent: user_agent.clone(),
            start_height: height as i32,
            relay: false,
        })
    }

    fn disconnect (&self, pid: PeerId) {
        if let Entry::Occupied(peer_entry) = self.peers.write().unwrap().entry(pid) {
            {
                let mut locked_peer = peer_entry.get().lock().unwrap();
                if let Some(ref waker) = locked_peer.disconnected_waker {
                    waker.wake();
                }
                locked_peer.disconnected_waker = None;
                locked_peer.stream.shutdown(Shutdown::Both).unwrap_or(());
            }
            peer_entry.remove();
        }
    }

    fn event_processor (&self, node: Arc<Node>, event: Event, pid: PeerId, iobuf: &mut [u8]) -> Result<(), SPVError> {
        let readiness = UnixReady::from(event.readiness());
        // check for error first
        if readiness.is_hup() || readiness.is_error() {
            info!("left us peer={}", pid);
            node.disconnected(pid)?;
            self.disconnect(pid);
        } else {
            // check for ability to write before read, to get rid of data before buffering more read
            // token should only be registered for write if there is a need to write
            // to avoid superfluous wakeups from poll
            if readiness.contains(Ready::writable()) {
                trace!("writeable peer={}", pid);

                // figure peer's entry in the peer map, provided it is still connected, ignore event if not
                if let Some(peer) = self.peers.read().unwrap().get(&pid) {
                    // get and lock the peer from the peer map entry
                    let mut locked_peer = peer.lock().unwrap();
                    loop {
                        let mut get_next = true;
                        // if there is previously unfinished write
                        if let Ok(len) = locked_peer.write_buffer.read_ahead(iobuf) {
                            if len > 0 {
                                trace!("try write {} bytes to peer={}", len, pid);
                                // try writing it out now
                                let mut wrote = 0;
                                while let Ok(wlen) = locked_peer.stream.write(&iobuf[wrote..len]) {
                                    if wlen == 0 {
                                        trace!("would block on peer={}", pid);
                                        // do not fetch next message until there is an unfinished write
                                        get_next = false;
                                        break;
                                    }
                                    trace!("wrote {} bytes to peer={}", wlen, pid);
                                    // advance buffer and drop used store
                                    locked_peer.write_buffer.advance(wlen);
                                    locked_peer.write_buffer.commit();
                                    wrote += wlen;
                                    if wrote == len {
                                        break;
                                    }
                                }
                            }
                        }
                        if get_next {
                            // get an outgoing message from the channel (if any)
                            if let Some(msg) = locked_peer.try_receive() {
                                // serialize the message
                                let raw = RawNetworkMessage { magic: self.magic, payload: msg };
                                trace!("next message {} to peer={}", raw.command(), pid);
                                // refill write buffer
                                encode(&raw, &mut locked_peer.write_buffer)?;
                            } else {
                                // no unfinished write and no outgoing message
                                // keep registered only for read events
                                trace!("done writing to peer={}", pid);
                                locked_peer.reregister_read()?;
                                break;
                            }
                        }
                    }
                }
            }
            // is peer readable ?
            if readiness.contains(Ready::readable()) {
                trace!("readable peer={}", pid);
                // collect incoming messages here
                // incoming messages are collected here for processing after release
                // of the lock on the peer map.
                let mut incoming = Vec::new();
                // disconnect if set
                let mut disconnect = false;
                // new handshake if set
                let mut handshake = false;
                // read lock peer map and retrieve peer
                if let Some(peer) = self.peers.read().unwrap().get(&pid) {
                    // lock the peer from the peer
                    let mut locked_peer = peer.lock().unwrap();
                    // read the peer's socket
                    if let Ok(len) = locked_peer.stream.read(iobuf) {
                        trace!("received {} bytes from peer={}", len, pid);
                        // accumulate in a buffer
                        locked_peer.read_buffer.write(&iobuf[0..len])?;
                        // extract messages from the buffer
                        while let Some(msg) = decode(&mut locked_peer.read_buffer)? {
                            trace!("received {} peer={}", msg.command(), pid);
                            // process handshake first
                            match locked_peer.process_handshake(&msg)? {
                                HandShake::Disconnect => {
                                    trace!("disconnecting peer={}", pid);
                                    // mark for disconnect outside of lock scope
                                    disconnect = true;
                                    break;
                                }
                                HandShake::Handshake => {
                                    // mark for connected outside of lock scope
                                    handshake = true;
                                }
                                HandShake::InProgress => {},
                                HandShake::Process => {
                                    // queue messages to process outside of locked scope
                                    incoming.push(msg);
                                }
                            }
                        }
                    }
                    else {
                        disconnect = true;
                    }
                }
                if disconnect {
                    info!("left us peer={}", pid);
                    node.disconnected(pid)?;
                    self.disconnect(pid);
                }
                else {
                    if handshake {
                        info!("connected peer={}", pid);
                        node.connected (pid)?;
                    }
                    // process queued incoming messages outside lock
                    // as process could call back to P2P
                    for msg in incoming {
                        trace!("processing {} for peer={}", msg.command(), pid);
                        match node.process (&msg.payload, pid)? {
                            ProcessResult::Ack => { trace!("ack {} peer={}", msg.command(), pid); },
                            ProcessResult::Ignored => { trace!("ignored {} peer={}", msg.command(), pid); }
                            ProcessResult::Disconnect => {
                                info!("disconnected peer={}", pid);
                                node.disconnected (pid)?;
                                self.disconnect(pid);
                            },
                            ProcessResult::Ban(increment) => {
                                let mut disconnect = false;
                                if let Some(peer) = self.peers.read().unwrap().get(&pid) {
                                    let mut locked_peer = peer.lock().unwrap();
                                    locked_peer.ban += increment;
                                    trace!("ban score {} for peer={}", locked_peer.ban, pid);
                                    if locked_peer.ban >= BAN {
                                       disconnect = true;
                                    }
                                }
                                if disconnect {
                                    // TODO DB update
                                    info!("banning peer={}", pid);
                                    node.disconnected(pid)?;
                                    self.disconnect(pid);
                                }
                            }
                            ProcessResult::Height(new_height) => {
                                if let Some(peer) = self.peers.read().unwrap().get(&pid) {
                                    let mut locked_peer = peer.lock().unwrap();
                                    let mut nv = locked_peer.version.clone().unwrap();
                                    nv.start_height = new_height as i32;
                                    locked_peer.version = Some(nv);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// run the message dispatcher loop
    /// this method does not return unless there is an error obtaining network events
    /// run in its own thread, which will process all network events
    pub fn run(&self, node: Arc<Node>) -> Result<(), io::Error>{
        trace!("start mio event loop");
        loop {
            // events buffer
            let mut events = Events::with_capacity(EVENT_BUFFER_SIZE);
            // IO buffer
            let mut iobuf = vec!(0u8; IO_BUFFER_SIZE);

            // get the next batch of events
            self.poll.poll(&mut events, None)?;

            // iterate over events
            for event in events.iter() {
                // construct the id of the peer the event concerns
                let pid = PeerId { token: event.token() };
                if let Err(error) = self.event_processor(node.clone(), event, pid, iobuf.as_mut_slice()) {
                    warn!("error {} peer={}", error.to_string(), pid);
                    debug!("error {:?} peer={}", error, pid);
                }
            }
        }
    }
}

// possible outcomes of the handshake with a peer
enum HandShake {
    Disconnect,
    InProgress,
    Handshake,
    Process
}

/// a peer
pub struct Peer {
    /// the peer's id for log messages
    pub pid: PeerId,
    // the event poller, shared with P2P, needed here to register for events
    poll: Arc<Poll>,
    // the connection to remote peer
    stream: TcpStream,
    // temporary buffer for not yet completely read incoming messages
    read_buffer: Buffer,
    // temporary buffer for not yet completely written outgoind messages
    write_buffer: Buffer,
    // did the remote peer already sent a verack?
    got_verack: bool,
    // own id, needed here to recognise that remote is actually the local peer
    nonce: u64,
    /// the version message the peer sent to us at connect
    pub version: Option<VersionMessage>,
    // channel into the event processing loop for outgoing messages
    sender: mpsc::Sender<NetworkMessage>,
    // channel into the event processing loop for outgoing messages
    receiver: mpsc::Receiver<NetworkMessage>,
    // is registered for write?
    writeable: AtomicBool,
    // connected and handshake complete?
    connected: Cell<bool>,
    // waker for handshake complete
    connected_waker: Option<Waker>,
    // waker for peer disconnected
    disconnected_waker: Option<Waker>,
    // ban score
    ban: u32
}

impl Peer {
    /// create a new peer
    pub fn new (pid: PeerId, poll: Arc<Poll>, addr: &SocketAddr, nonce: u64) -> Result<Peer, SPVError> {
        let stream = TcpStream::connect(addr)?;
        let (sender, receiver) = mpsc::channel();
        let peer = Peer{pid, poll: poll.clone(), stream, read_buffer: Buffer::new(), write_buffer: Buffer::new(),
            got_verack: false, nonce, version: None, sender, receiver, writeable: AtomicBool::new(false),
            connected: Cell::new(false), connected_waker: None, disconnected_waker: None, ban: 0 };
        peer.register_write()?;
        Ok(peer)
    }

    // register for peer readable events
    fn reregister_read(&self) -> Result<(), SPVError> {
        if self.writeable.swap(false, Ordering::Acquire) {
            trace!("re-register for read peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::readable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }

    /// send a message to P2P network
    pub fn send (&self, msg: &NetworkMessage) -> Result<(), SPVError> {
        // send to outgoing message channel
        self.sender.send(msg.clone()).map_err(| _ | SPVError::Generic("can not send to peer queue".to_owned()))?;
        // register for writable peer events since we have outgoing message
        self.reregister_write()?;
        Ok(())
    }

    // register for peer writable events
    fn reregister_write(&self) -> Result<(), SPVError> {
        if !self.writeable.swap(true, Ordering::Acquire) {
            trace!("re-register for write peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }


    // register for peer writable events
    fn register_write(&self) -> Result<(), SPVError> {
        if !self.writeable.swap(true, Ordering::Acquire) {
            trace!("register for write peer={}", self.pid);
            self.poll.register(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }


    // try to receive a message from the outgoing message channel
    fn try_receive (&self) -> Option<NetworkMessage> {
        if let Ok (msg) = self.receiver.try_recv() {
            Some (msg)
        } else {
            None
        }
    }

    // process handshake, returning:
    // Handshake::Disconnect - for misbehaving or useless remote peers
    // Handshake::InProgress - for handshake in progress that may still fail
    // Handshake::Handshake - for finished handshake, this will be returned only once
    // Handshake::Process - handshake was perfect, go ahead with regular processing
    fn process_handshake(&mut self, msg: &RawNetworkMessage) -> Result<HandShake, SPVError> {
        if !(self.version.is_some() && self.got_verack) {
            // before handshake complete
            match msg.payload {
                NetworkMessage::Version(ref version) => {
                    if self.version.is_some() {
                        return Ok(HandShake::Disconnect);
                    }

                    if version.nonce == self.nonce {
                        return Ok(HandShake::Disconnect);
                    } else {
                        // want to connect to full nodes upporting segwit
                        if version.services & 9 != 9 || version.version < 70013 {
                            return Ok(HandShake::Disconnect);
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
                        return Ok(HandShake::Disconnect);
                    }
                    trace!("got verack peer={}", self.pid);
                    self.got_verack = true;
                }
                _ => {
                    trace!("misbehaving peer={}", self.pid);
                    return Ok(HandShake::Disconnect);
                }
            };
            if self.version.is_some() && self.got_verack {
                self.connected.set(true);
                if let Some(ref waker) = self.connected_waker {
                    waker.wake();
                }
                return Ok(HandShake::Handshake)
            }
            else {
                return Ok(HandShake::InProgress)
            }
        }
        Ok(HandShake::Process)
    }
}

// A buffer that can be:
// * rolled back and re-read from last commit
// * read ahead without moving read position
// * advance position
struct Buffer {
    // a deque of chunks
    chunks: VecDeque<Vec<u8>>,
    // pos.0 - current chunk
    // pos.1 - position to read next in the current chunk
    pos: (usize, usize),
    // a copy of pos at last checkpoint call
    checkpoint: (usize, usize)
}

impl Buffer {
    // create new buffer
    fn new () -> Buffer {
        Buffer{ chunks: VecDeque::new(), pos: (0, 0), checkpoint: (0, 0) }
    }

    // rollback to last commit
    fn rollback (&mut self) {
        self.pos = self.checkpoint;
    }

    // checkpoint and drop already read content
    fn commit (&mut self) {
        // drop read chunks
        self.chunks.drain(0 .. self.pos.0);
        // current chunk is now the first
        self.pos.0 = 0;
        self.checkpoint = self.pos;
    }

    // read without advancing position
    // subsequent read would deliver the same data again
    fn read_ahead (&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let mut pos = (self.pos.0, self.pos.1);
        if self.chunks.len() == 0 {
            // no chunks -> no content
            Ok(0)
        }
        else {
            // number of bytes already collected for the read
            let mut have = 0;
            // until read enough
            while have < buf.len() {
                // current chunk
                let current = &self.chunks[pos.0];
                // number of bytes available to read from current chunk
                let available = min(buf.len() - have, current.len() - pos.1);
                // copy those
                buf[have..have+available].copy_from_slice(&current[pos.1..pos.1 + available]);
                // move pointer
                pos.1 += available;
                // have more
                have += available;
                // if current chunk was wholly read
                if pos.1 == current.len() {
                    // there are more chunks
                    if pos.0 < self.chunks.len() - 1 {
                        // move pointer to begin of next chunk
                        pos.0 += 1;
                        pos.1 = 0;
                    }
                    else {
                        // we can't have more now
                        break;
                    }
                }
            }
            // return the number of bytes that could be read
            Ok(have)
        }
    }

    // advance position by len
    fn advance (&mut self, len: usize) -> usize {
        let mut have = 0;
        // until read enough
        while have < len {
            // current chunk
            let current = &self.chunks[self.pos.0];
            // number of bytes available to read from current chunk
            let available = min(len - have, current.len() - self.pos.1);
            // move pointer
            self.pos.1 += available;
            // have more
            have += available;
            // if current chunk was wholly read
            if self.pos.1 == current.len() {
                // there are more chunks
                if self.pos.0 < self.chunks.len() - 1 {
                    // move pointer to begin of next chunk
                    self.pos.0 += 1;
                    self.pos.1 = 0;
                } else {
                    // we can't have more now
                    break;
                }
            }
        }
        // return the number of bytes that could be read
        have
    }

    // read and advance position in one step
    fn read_advance (&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if self.chunks.len() == 0 {
            // no chunks -> no content
            Ok(0)
        }
        else {
            // number of bytes already collected for the read
            let mut have = 0;
            // until read enough
            while have < buf.len() {
                // current chunk
                let current = &self.chunks[self.pos.0];
                // number of bytes available to read from current chunk
                let available = min(buf.len() - have, current.len() - self.pos.1);
                // copy those
                buf[have..have+available].copy_from_slice(&current[self.pos.1..self.pos.1 + available]);
                // move pointer
                self.pos.1 += available;
                // have more
                have += available;
                // if current chunk was wholly read
                if self.pos.1 == current.len() {
                    // there are more chunks
                    if self.pos.0 < self.chunks.len() - 1 {
                        // move pointer to begin of next chunk
                        self.pos.0 += 1;
                        self.pos.1 = 0;
                    }
                    else {
                        // we can't have more now
                        break;
                    }
                }
            }
            // return the number of bytes that could be read
            Ok(have)
        }
    }
}

// write adapter for above buffer
impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if buf.len() > 0 {
            // number of chunks in buffer
            let mut nc = self.chunks.len();
            // if no chunks or append to last chunk would create a too big chunk
            if nc == 0 || (buf.len() + self.chunks[nc - 1].len()) > IO_BUFFER_SIZE {
                // allocate and append a new chunk sufficient to hold buf but not smaller than IO_BUFFER_SIZE
                self.chunks.push_back(Vec::with_capacity(max(buf.len(), IO_BUFFER_SIZE)));
                nc += 1;
            }
            // append buf to current chunk
            self.chunks[nc - 1].extend_from_slice(buf);
        }
        Ok(buf.len())
    }
    // nop
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

// read adapter for above buffer
impl Read for Buffer {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.read_advance(buf)
    }
}

// encode a message in Bitcoin's wire format extending the given buffer
fn encode(item: &RawNetworkMessage, dst: &mut Buffer) -> Result<(), io::Error> {
    match item.consensus_encode(&mut RawEncoder::new(dst)) {
        Ok(_) => Ok(()),
        Err(e) => Err(io::Error::new(io::ErrorKind::WriteZero, e))
    }
}

// decode a message from the buffer if possible
fn decode(src: &mut Buffer) -> Result<Option<RawNetworkMessage>, io::Error> {
    // attempt to decode
    let mut raw = RawDecoder::new(src);
    let decode: Result<RawNetworkMessage, util::Error> =
        ConsensusDecodable::consensus_decode(&mut raw);
    let src = raw.into_inner();

    match decode {
        Ok(m) => {
            // success: free the read data in buffer and return the message
            src.commit();
            Ok(Some(m))
        }
        Err(util::Error::ByteOrder(_)) => {
            // failure: partial message, rollback to last commit and retry later
            src.rollback();
            Ok(None)
        },
        Err(e) => {
            // some serious error (often checksum)
            trace!("invalid data in codec: {}", e);
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}
