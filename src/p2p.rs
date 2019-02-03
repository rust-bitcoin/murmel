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
//! # P2P network communication
//!
//! This module establishes network connections and routes messages between the P2P network and this node
//!

use bitcoin::{
    consensus::{Decodable, Encodable, encode}
};
use bitcoin::network::{
    address::Address,
    constants::Network,
    message::{NetworkMessage, RawNetworkMessage},
    message_network::VersionMessage
};

use error::MurmelError;
use futures::{
    Async, Future, future, FutureExt,
    task::{Context, Waker}
};
use mio::{
    Event, Events, net::{TcpListener, TcpStream}, Poll, PollOpt, Ready,
    Token,
    unix::UnixReady
};
use rand::{RngCore, thread_rng};
use std::{
    cmp::{max, min},
    collections::{HashMap, VecDeque},
    fmt,
    io,
    io::{Read, Write},
    net::{Shutdown, SocketAddr},
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc, Mutex,
           RwLock
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH}
};


const IO_BUFFER_SIZE:usize = 1024*1024;
const EVENT_BUFFER_SIZE:usize = 1024;
const CONNECT_TIMEOUT_SECONDS: u64 = 30;
const BAN :u32 = 100;

pub const SERVICE_BLOCKS:u64 = 1;
pub const SERVICE_WITNESS:u64 =  1 << 3;
pub const SERVICE_FILTERS:u64 = 1 << 6;
/// A peer's Id
#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct PeerId {
    // mio token used in networking
    token: Token
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.token.0)?;
        Ok(())
    }
}
type PeerMap = HashMap<PeerId, Mutex<Peer>>;

#[derive(Clone)]
pub enum PeerMessage {
    Message(PeerId, NetworkMessage),
    Connected(PeerId),
    Disconnected(PeerId)
}

impl PeerMessage {
    pub fn peer_id (&self) -> PeerId {
        match self {
            PeerMessage::Message(pid, _) |
            PeerMessage::Connected(pid) |
            PeerMessage::Disconnected(pid) => pid.clone()
        }
    }
}

pub enum P2PControl {
    Send(PeerId, NetworkMessage),
    Broadcast(NetworkMessage),
    Ban(PeerId, u32),
    Height(u32),
    Bind(SocketAddr)
}

type P2PControlReceiver = mpsc::Receiver<P2PControl>;

#[derive(Clone)]
pub struct P2PControlSender {
    sender: Arc<Mutex<mpsc::Sender<P2PControl>>>,
    peers: Arc<RwLock<PeerMap>>,
    pub back_pressure: usize
}

impl P2PControlSender {
    fn new (sender: mpsc::Sender<P2PControl>, peers: Arc<RwLock<PeerMap>>, back_pressure: usize) -> P2PControlSender {
        P2PControlSender { sender: Arc::new(Mutex::new(sender)), peers, back_pressure }
    }

    pub fn send (&self, control: P2PControl) {
        self.sender.lock().unwrap().send(control).expect("P2P control send failed");
    }

    pub fn send_network (&self, peer: PeerId, msg: NetworkMessage) {
        self.send(P2PControl::Send(peer, msg))
    }

    pub fn broadcast (&self, msg: NetworkMessage) {
        self.send(P2PControl::Broadcast(msg))
    }

    pub fn ban(&self, peer: PeerId, increment: u32) {
        self.send(P2PControl::Ban(peer, increment))
    }

    pub fn peer_version (&self, peer: PeerId) -> Option<VersionMessage> {
        if let Some(peer) = self.peers.read().unwrap().get(&peer) {
            let locked_peer = peer.lock().unwrap();
            return locked_peer.version.clone();
        }
        None
    }

    pub fn peers (&self) -> Vec<PeerId> {
        self.peers.read().unwrap().keys().cloned().collect::<Vec<_>>()
    }
}

#[derive(Clone)]
pub enum PeerSource {
    Outgoing(SocketAddr),
    Incoming(Arc<TcpListener>)
}

/// a map of peer id to peers
pub type PeerMessageReceiver = mpsc::Receiver<PeerMessage>;

#[derive(Clone)]
pub struct PeerMessageSender {
    sender: Option<Arc<Mutex<mpsc::SyncSender<PeerMessage>>>>
}

impl PeerMessageSender {
    pub fn new (sender: mpsc::SyncSender<PeerMessage>) -> PeerMessageSender {
        PeerMessageSender { sender: Some(Arc::new(Mutex::new(sender))) }
    }

    pub fn dummy () -> PeerMessageSender {
        PeerMessageSender{ sender: None }
    }

    pub fn send (&self, msg: PeerMessage) {
        if let Some(ref sender) = self.sender {
            sender.lock().unwrap().send(msg).expect("P2P message send failed");
        }
    }

    pub fn send_network(&self, peer: PeerId, msg: NetworkMessage) {
        if let Some(ref sender) = self.sender {
            sender.lock().unwrap().send(PeerMessage::Message(peer, msg)).expect("P2P message send failed");
        }
    }
}

/// The P2P network layer
pub struct P2P {
    pub network: Network,
    // sender to the dispatcher of incoming messages
    dispatcher: PeerMessageSender,
    // network specific message prefix
    magic: u32,
    // This node's identifier on the network (random)
    nonce: u64,
    // height of the blockchain tree trunk
    height: AtomicUsize,
    // This node's human readable type identification
    user_agent: String,
    // The collection of connected peers
    peers: Arc<RwLock<PeerMap>>,
    // The poll object of the async IO layer (mio)
    // access to this is shared by P2P and Peer
    poll: Arc<Poll>,
    // next peer id
    // atomic only for interior mutability
    next_peer_id: AtomicUsize,
    // waker
    waker: Arc<Mutex<HashMap<PeerId, Waker>>>,
    // server
    listener: Arc<Mutex<HashMap<Token, Arc<TcpListener>>>>,
    // this node's maximum protocol version
    max_protocol_version: u32,
    // is this a filter (BIP157) server?
    filter_server: bool
}

impl P2P {
    /// create a new P2P network controller
    pub fn new(user_agent: String, network: Network, height: u32, max_protocol_version: u32, filter_server: bool, dispatcher: PeerMessageSender, back_pressure: usize) -> (Arc<P2P>, P2PControlSender) {
        let (control_sender, control_receiver) = mpsc::channel();

        let mut rng =  thread_rng();
        let magic = network.magic();

        let peers = Arc::new(RwLock::new(PeerMap::new()));

        let p2p = Arc::new(P2P {
            network: network,
            dispatcher,
            magic,
            nonce: rng.next_u64(),
            height: AtomicUsize::new(height as usize),
            user_agent,
            peers: peers.clone(),
            poll: Arc::new(Poll::new().unwrap()),
            next_peer_id: AtomicUsize::new(0),
            waker: Arc::new(Mutex::new(HashMap::new())),
            listener: Arc::new(Mutex::new(HashMap::new())),
            max_protocol_version: max_protocol_version,
            filter_server
        });

        let p2p2 = p2p.clone();

        thread::spawn(move || p2p2.control_loop(control_receiver));

        (p2p, P2PControlSender::new(control_sender, peers, back_pressure))
    }

    fn control_loop (&self, receiver: P2PControlReceiver) {
        while let Ok(control) = receiver.recv() {
            match control {
                P2PControl::Ban(peer_id, score) => {
                    self.ban(peer_id, score);
                },
                P2PControl::Height(height) => {
                    self.height.store (height as usize, Ordering::Relaxed);
                }
                P2PControl::Bind(addr) => {
                    match self.add_listener(&addr) {
                        Ok(()) => info!("listen to {}", addr),
                        Err(err) => info!("failed to listen to {} with {}", addr, err)
                    }
                },
                P2PControl::Broadcast(message) => {
                    for peer in self.peers.read().unwrap().values() {
                        peer.lock().unwrap().send(message.clone()).expect("could not send to peer");
                    }
                }
                P2PControl::Send(peer_id, message) => {
                    if let Some (peer) = self.peers.read().unwrap().get (&peer_id) {
                        peer.lock().unwrap().send(message).expect("could not send to peer");
                    }
                }
            }
        }
        panic!("P2P Control loop failed");
    }

    fn add_listener (&self, bind: &SocketAddr) -> Result<(), io::Error> {
        let listener = TcpListener::bind(bind)?;
        let token = Token(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        self.poll.register(&listener, token, Ready::readable(), PollOpt::edge())?;
        self.listener.lock().unwrap().insert(token, Arc::new(listener));
        Ok(())
    }

    /// return a future that does not complete until the peer is connected
    pub fn add_peer (&self, source: PeerSource) -> Box<Future<Item=SocketAddr, Error=MurmelError> + Send> {
        // new token, never re-using previously connected peer's id
        // so log messages are easier to follow
        let token = Token(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        let pid = PeerId{token};

        let connect = self.connect_peer_with_timeout(pid,CONNECT_TIMEOUT_SECONDS, source.clone());

        let peers = self.peers.clone();
        let peers2 = self.peers.clone();

        Box::new(connect
            .map_err (move |e| {
                // remove peers and candidates entry
                info!("timeout on handshake peer={}", pid);
                peers2.write().unwrap().remove(&pid);
                e
            })
            .and_then (move|address| {
            Box::new(future::poll_fn (move | _ | {
                // retrieve peer from peer map
                if let Some(_) = peers.read().unwrap().get(&pid) {
                    Ok(Async::Pending)
                } else {
                    trace!("peer {:?} finished", address);
                    Ok(Async::Ready(address))
                }
            }
            ))}))
    }

    /// return a future that resolves to a connected (handshake perfect) peer or timeout
    pub fn connect_peer_with_timeout (&self, pid: PeerId, seconds: u64, source: PeerSource) -> Box<Future<Item=SocketAddr, Error=MurmelError> + Send> {
        use futures_timer::FutureExt;

        Box::new(self.connect_peer(pid, source).timeout(Duration::from_secs(seconds)))
    }

    // connect a peer
    fn connect_peer(&self, pid: PeerId, source: PeerSource) -> Box<Future<Item=SocketAddr, Error=MurmelError> + Send> {
        let peers = self.peers.clone();
        let waker = self.waker.clone();

        // initiate connection
        match self.initiate_connect(pid,source) {
            // connection initiated, resolve to a future that polls for handshake complete
            Ok(addr) => Box::new(
                future::poll_fn (move |ctx|
                    {
                        // retrieve peer from peer map
                        if let Some(peer) = peers.read().unwrap().get(&pid) {
                            // return pid if peer is connected (handshake perfect)
                            if peer.lock().unwrap().connected {
                                trace!("woke up to handshake");
                                Ok(Async::Ready(addr))
                            } else {
                                waker.lock().unwrap().insert(pid, ctx.waker().clone());
                                Ok(Async::Pending)
                            }
                        } else {
                            // timeout will pick up
                            Ok(Async::Pending)
                        }
                    })),
            // resolve to an error returning future if initiation fails
            Err(e) => Box::new(future::err(e))
        }
    }

    // initiate connection to peer
    fn initiate_connect(&self, pid: PeerId, source: PeerSource) -> Result<SocketAddr, MurmelError> {
        let outgoing;
        let addr;
        let stream;
        match source {
            PeerSource::Outgoing(a) => {
                addr = a;
                outgoing = true;
                info!("trying outgoing connect to {} peer={}", addr, pid);
                stream = TcpStream::connect(&addr)?;
            },
            PeerSource::Incoming(listener) => {
                let (s, a) = listener.accept()?;
                addr = a;
                stream = s;
                info!("trying incoming connect to {} peer={}", addr, pid);
                outgoing = false;
            }
        };

        // create lock protected peer object
        let peer = Mutex::new(Peer::new(pid, stream,self.poll.clone(), outgoing)?);

        let mut peers = self.peers.write().unwrap();

        // add to peer map
        peers.insert(pid, peer);

        let stored_peer = peers.get(&pid).unwrap();

        if outgoing {
            stored_peer.lock().unwrap().register_write()?;
        } else {
            stored_peer.lock().unwrap().register_read()?;
        }
        if outgoing {
            // send this node's version message to peer
            peers.get(&pid).unwrap().lock().unwrap().send(self.version(&addr, self.max_protocol_version))?;
        }

        Ok(addr)
    }

    // compile this node's version message for outgoing connections
    fn version (&self, remote: &SocketAddr, max_protocol_version: u32) -> NetworkMessage {
        // now in unix time
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let services = if self.listener.lock().unwrap().is_empty() {
            0
        } else {
            SERVICE_BLOCKS + SERVICE_WITNESS + if self.filter_server {
                // announce that this node is capable of serving BIP157 messages
                SERVICE_FILTERS
            }
            else {
                0
            }
        };

        // build message
        NetworkMessage::Version(VersionMessage {
            version: min(max_protocol_version, self.max_protocol_version),
            services,
            timestamp,
            receiver: Address::new(remote, 1),
            // sender is only dummy
            sender: Address::new(remote, 1),
            nonce: self.nonce,
            user_agent: self.user_agent.clone(),
            start_height: self.height.load(Ordering::Relaxed) as i32,
            relay: false, // there is no mempool here therefore no use for inv's of transactions
        })
    }

    fn disconnect (&self, pid: PeerId) {
        {
            let mut wakers = self.waker.lock().unwrap();
            if let Some(waker) = wakers.get(&pid) {
                trace!("waking for disconnect");
                waker.wake();
            }
            wakers.remove(&pid);
        }
        {
            let mut peers = self.peers.write().unwrap();
            if let Some(peer) = peers.get(&pid) {
                peer.lock().unwrap().stream.shutdown(Shutdown::Both).unwrap_or(());
            }
            peers.remove(&pid);
        }
        self.dispatcher.send(PeerMessage::Disconnected(pid));
    }

    fn connected(&self, pid: PeerId) {
        self.dispatcher.send(PeerMessage::Connected(pid));
    }

    fn ban (&self, pid: PeerId, increment: u32) {
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
            self.disconnect(pid);
        }
    }

    fn event_processor (&self, event: Event, pid: PeerId, needed_services: u64, iobuf: &mut [u8]) -> Result<(), MurmelError> {
        let readiness = UnixReady::from(event.readiness());
        // check for error first
        if readiness.is_hup() || readiness.is_error() {
            info!("left us peer={}", pid);
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
                        locked_peer.read_buffer.write_all(&iobuf[0..len])?;
                        // extract messages from the buffer
                        while let Some(msg) = decode(&mut locked_peer.read_buffer)? {
                            trace!("received {} peer={}", msg.command(), pid);
                            if locked_peer.connected {
                                // regular processing after handshake
                                incoming.push(msg);
                            }
                            else {
                                // have to get both version and verack to complete handhsake
                                if !(locked_peer.version.is_some() && locked_peer.got_verack) {
                                    // before handshake complete
                                    match msg.payload {
                                        NetworkMessage::Version(ref version) => {
                                            if locked_peer.version.is_some() {
                                                // repeated version
                                                disconnect = true;
                                                break;
                                            }
                                            if version.nonce == self.nonce {
                                                // connect to myself
                                                disconnect = true;
                                                break;
                                            } else {
                                                if version.version < 70001 || (needed_services & version.services) != needed_services {
                                                    debug!("rejecting peer of version {} and services {:b} peer={}", version.version, version.services, pid);
                                                    disconnect = true;
                                                    break;
                                                } else {
                                                    if !locked_peer.outgoing {
                                                        // send own version message to incoming peer
                                                        let addr = locked_peer.stream.peer_addr()?;
                                                        trace!("send version to incoming connection {}", addr);
                                                        // do not show higher version than the peer speaks
                                                        let version = self.version (&addr, version.version);
                                                        locked_peer.send(version)?;
                                                    }
                                                    debug!("accepting peer of version {} and services {:b} peer={}", version.version, version.services, pid);
                                                    // acknowledge version message received
                                                    locked_peer.send(NetworkMessage::Verack)?;
                                                    // all right, remember this peer
                                                    info!("client {} height: {} peer={}", version.user_agent, version.start_height, pid);
                                                    let mut vm = version.clone();
                                                    // reduce protocol version to our capabilities
                                                    vm.version = min (vm.version, self.max_protocol_version);
                                                    locked_peer.version = Some(vm);
                                                }
                                            }
                                        }
                                        NetworkMessage::Verack => {
                                            if locked_peer.got_verack {
                                                // repeated verack
                                                disconnect = true;
                                                break;
                                            }
                                            trace!("got verack peer={}", pid);
                                            locked_peer.got_verack = true;
                                        }
                                        _ => {
                                            trace!("misbehaving peer={}", pid);
                                            // some other message before handshake
                                            disconnect = true;
                                            break;
                                        }
                                    };
                                    if locked_peer.version.is_some() && locked_peer.got_verack {
                                        locked_peer.connected = true;
                                        handshake = true;
                                    }
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
                    self.disconnect(pid);
                }
                else {
                    if handshake {
                        info!("handshake peer={}", pid);
                        self.connected (pid);
                        if let Some(w) = self.waker.lock().unwrap().get(&pid) {
                            trace!("waking for handshake");
                            w.wake();
                        }
                    }
                    // process queued incoming messages outside lock
                    // as process could call back to P2P
                    for msg in incoming {
                        trace!("processing {} for peer={}", msg.command(), pid);
                        self.dispatcher.send(PeerMessage::Message(pid, msg.payload));
                    }
                }
            }
        }
        Ok(())
    }

    /// run the message dispatcher loop
    /// this method does not return unless there is an error obtaining network events
    /// run in its own thread, which will process all network events
    pub fn run(&self, needed_services: u64, ctx: &mut Context) -> Result<(), io::Error>{
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
                // check for listener
                if let Some(server) = self.is_listener(event.token()) {
                    trace!("incoming connection request");
                    ctx.executor().spawn(
                        Box::new(self.add_peer(PeerSource::Incoming(server))
                        .map(|_|()).or_else(|_|Ok(()))))
                        .expect("can not spawn task for incoming connection");
                }
                else {
                    // construct the id of the peer the event concerns
                    let pid = PeerId { token: event.token() };
                    if let Err(error) = self.event_processor(event, pid, needed_services, iobuf.as_mut_slice()) {
                        use std::error::Error;

                        warn!("error {} peer={}", error.to_string(), pid);
                        debug!("error {:?} peer={}", error.cause(), pid);
                    }
                }
            }
        }
    }

    fn is_listener(&self, token: Token) -> Option<Arc<TcpListener>> {
        if let Some(server) = self.listener.lock().unwrap().get(&token) {
            return Some(server.clone())
        }
        None
    }
}

/// a peer
struct Peer {
    /// the peer's id for log messages
    pub pid: PeerId,
    // the event poller, shared with P2P, needed here to register for events
    poll: Arc<Poll>,
    // the connection to remote peer
    stream: TcpStream,
    // temporary buffer for not yet completely read incoming messages
    read_buffer: Buffer,
    // temporary buffer for not yet completely written outgoing messages
    write_buffer: Buffer,
    // did the remote peer already sent a verack?
    got_verack: bool,
    /// the version message the peer sent to us at connect
    pub version: Option<VersionMessage>,
    // channel into the event processing loop for outgoing messages
    sender: mpsc::Sender<NetworkMessage>,
    // channel into the event processing loop for outgoing messages
    receiver: mpsc::Receiver<NetworkMessage>,
    // is registered for write?
    writeable: AtomicBool,
    // connected and handshake complete?
    connected: bool,
    // ban score
    ban: u32,
    // outgoing or incoming connection
    outgoing: bool
}

impl Peer {
    /// create a new peer
    pub fn new (pid: PeerId, stream: TcpStream, poll: Arc<Poll>, outgoing: bool) -> Result<Peer, MurmelError> {
        let (sender, receiver) = mpsc::channel();
        let peer = Peer{pid, poll: poll.clone(), stream, read_buffer: Buffer::new(), write_buffer: Buffer::new(),
            got_verack: false, version: None, sender, receiver, writeable: AtomicBool::new(false),
            connected: false, ban: 0, outgoing };
        Ok(peer)
    }

    // re-register for peer readable events
    fn reregister_read(&self) -> Result<(), MurmelError> {
        if self.writeable.swap(false, Ordering::Acquire) {
            trace!("re-register for read peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::readable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }

    // register for peer readable events
    fn register_read(&self) -> Result<(), MurmelError> {
        trace!("register for read peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::readable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        self.writeable.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// send a message to P2P network
    pub fn send (&self, msg: NetworkMessage) -> Result<(), MurmelError> {
        // send to outgoing message channel
        self.sender.send(msg).map_err(| _ | MurmelError::Downstream("can not send to peer queue".to_owned()))?;
        // register for writable peer events since we have outgoing message
        self.reregister_write()?;
        Ok(())
    }

    // register for peer writable events
    fn reregister_write(&self) -> Result<(), MurmelError> {
        if !self.writeable.swap(true, Ordering::Acquire) {
            trace!("re-register for write peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }

    // register for peer writable events
    fn register_write(&self) -> Result<(), MurmelError> {
        trace!("register for write peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        self.writeable.store(true, Ordering::Relaxed);
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
fn encode(item: &RawNetworkMessage, mut dst: &mut Buffer) -> Result<(), io::Error> {
    match item.consensus_encode(&mut dst) {
        Ok(_) => Ok(()),
        Err(e) => Err(io::Error::new(io::ErrorKind::WriteZero, e))
    }
}

// decode a message from the buffer if possible
fn decode(src: &mut Buffer) -> Result<Option<RawNetworkMessage>, io::Error> {
    // attempt to decode
    let decode: Result<RawNetworkMessage, encode::Error> =
        Decodable::consensus_decode(src);

    match decode {
        Ok(m) => {
            // success: free the read data in buffer and return the message
            src.commit();
            Ok(Some(m))
        }
        Err(encode::Error::Io(e)) => {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                // need more data, rollback and retry after additional read
                src.rollback();
                return Ok(None)
            } else {
                return Err(e);
            }
        },
        Err(e) => {
            Err(io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }
}
