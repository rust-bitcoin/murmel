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
    consensus::{Decodable, encode}
};
use bitcoin::network::{
    address::Address,
    constants::Network,
    message::{NetworkMessage, RawNetworkMessage},
    message_network::VersionMessage
};

use crate::error::Error;
use futures::{Poll as Async, Future, future, FutureExt, task::{Waker}, TryFutureExt};
use log::{info, trace, debug, error};
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
    str::FromStr,
    sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}, mpsc, Mutex,
           RwLock
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH}
};
use std::marker::PhantomData;
use bitcoin::consensus::serialize;
use futures::task::{Spawn, SpawnExt};

const IO_BUFFER_SIZE:usize = 1024*1024;
const EVENT_BUFFER_SIZE:usize = 1024;
const CONNECT_TIMEOUT_SECONDS: u64 = 5;
const BAN :u32 = 100;

/// do we serve blocks?
pub const SERVICE_BLOCKS:u64 = 1;
/// requires segwit support
pub const SERVICE_WITNESS:u64 =  1 << 3;
/// require filters
pub const SERVICE_FILTERS:u64 = 1 << 6;
/// A peer's Id
#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct PeerId {
    network: &'static str,
    // mio token used in networking
    token: Token
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}-{}", self.network, self.token.0)?;
        Ok(())
    }
}
type PeerMap<Message> = HashMap<PeerId, Mutex<Peer<Message>>>;

/// A message from network to downstream
#[derive(Clone)]
pub enum PeerMessage<Message: Send + Sync + Clone> {
    Outgoing(Message),
    Incoming(PeerId, Message),
    Connected(PeerId, Option<SocketAddr>),
    Disconnected(PeerId, bool) // true if banned
}

pub enum P2PControl<Message: Clone> {
    Send(PeerId, Message),
    Broadcast(Message),
    Ban(PeerId, u32),
    Disconnect(PeerId),
    Height(u32),
    Bind(SocketAddr)
}

type P2PControlReceiver<Message> = mpsc::Receiver<P2PControl<Message>>;

#[derive(Clone)]
pub struct P2PControlSender<Message: Clone> {
    sender: Arc<Mutex<mpsc::Sender<P2PControl<Message>>>>,
    peers: Arc<RwLock<PeerMap<Message>>>,
    pub back_pressure: usize
}

impl<Message: Send + Sync + Clone> P2PControlSender<Message> {
    fn new (sender: mpsc::Sender<P2PControl<Message>>, peers: Arc<RwLock<PeerMap<Message>>>, back_pressure: usize) -> P2PControlSender<Message> {
        P2PControlSender { sender: Arc::new(Mutex::new(sender)), peers, back_pressure }
    }

    pub fn send (&self, control: P2PControl<Message>) {
        self.sender.lock().unwrap().send(control).expect("P2P control send failed");
    }

    pub fn send_network (&self, peer: PeerId, msg: Message) {
        self.send(P2PControl::Send(peer, msg))
    }

    pub fn send_random_network (&self, msg: Message) -> Option<PeerId> {
        let peers = self.peers.read().unwrap().keys().cloned().collect::<Vec<PeerId>>();
        if peers.len() > 0 {
            let peer = peers[(thread_rng().next_u32() % peers.len() as u32) as usize];
            self.send(P2PControl::Send(peer, msg));
            return Some(peer);
        }
        None
    }

    pub fn broadcast (&self, msg: Message) {
        self.send(P2PControl::Broadcast(msg))
    }

    pub fn ban(&self, peer: PeerId, increment: u32) {
        debug!("increase ban score with {} peer={}", increment, peer);
        self.send(P2PControl::Ban(peer, increment))
    }

    pub fn peer_version (&self, peer: PeerId) -> Option<VersionCarrier> {
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
pub type PeerMessageReceiver<Message> = mpsc::Receiver<PeerMessage<Message>>;

#[derive(Clone)]
pub struct PeerMessageSender<Message: Send + Sync + Clone> {
    sender: Option<Arc<Mutex<mpsc::SyncSender<PeerMessage<Message>>>>>
}

impl<Message: Send + Sync + Clone> PeerMessageSender<Message> {
    pub fn new (sender: mpsc::SyncSender<PeerMessage<Message>>) -> PeerMessageSender<Message> {
        PeerMessageSender { sender: Some(Arc::new(Mutex::new(sender))) }
    }

    pub fn dummy () -> PeerMessageSender<Message> {
        PeerMessageSender{ sender: None }
    }

    pub fn send (&self, msg: PeerMessage<Message>) {
        if let Some(ref sender) = self.sender {
            sender.lock().unwrap().send(msg).expect("P2P message send failed");
        }
    }
}

pub trait Command {
    fn command(&self)->String;
}

impl Command for RawNetworkMessage {
    fn command(&self) -> String {
        self.command()
    }
}

pub trait Version {
    fn is_verack(&self) ->bool;
    fn is_version(&self) -> Option<VersionCarrier>;
}

#[derive(Clone)]
pub struct VersionCarrier {
    /// The P2P network protocol version
    pub version: u32,
    /// A bitmask describing the services supported by this node
    pub services: u64,
    /// The time at which the `version` message was sent
    pub timestamp: u64,
    /// The network address of the peer receiving the message
    pub receiver: Address,
    /// The network address of the peer sending the message
    pub sender: Address,
    /// A random nonce used to detect loops in the network
    pub nonce: u64,
    /// A string describing the peer's software
    pub user_agent: String,
    /// The height of the maximum-work blockchain that the peer is aware of
    pub start_height: u32,
    /// Whether the receiving peer should relay messages to the sender; used
    /// if the sender is bandwidth-limited and would like to support bloom
    /// filtering. Defaults to true.
    pub relay: bool
}

impl Version for NetworkMessage {
    fn is_version(&self) -> Option<VersionCarrier> {
        match self {
            NetworkMessage::Version(v) => {
                Some(VersionCarrier {
                    version: v.version,
                    services: v.services,
                    timestamp: v.timestamp as u64,
                    receiver: v.receiver.clone(),
                    sender: v.sender.clone(),
                    nonce: v.nonce,
                    user_agent: v.user_agent.clone(),
                    start_height: v.start_height as u32,
                    relay: v.relay
                })
            },
            _ => None
        }
    }

    fn is_verack(&self) -> bool {
        match self {
            NetworkMessage::Verack => true,
            _ => false
        }
    }

}

pub trait P2PConfig<Message: Version + Send + Sync + 'static, Envelope: Command + Send + Sync + 'static> {
    fn version (&self, remote: &SocketAddr, max_protocol_version: u32) -> Message;
    fn nonce(&self) -> u64;
    fn magic(&self) -> u32;
    fn user_agent(&self) -> &str;
    fn get_height(&self) -> u32;
    fn set_height(&self, height: u32);
    fn max_protocol_version(&self) -> u32;
    fn min_protocol_version(&self) -> u32;
    fn verack(&self) -> Message;
    fn wrap(&self, m: Message) -> Envelope;
    fn unwrap(&self, e: Envelope) -> Result<Message, io::Error>;
    fn encode(&self, item: &Envelope, dst: &mut Buffer) -> Result<(), io::Error>;
    fn decode(&self, src: &mut Buffer) -> Result<Option<Envelope>, io::Error>;
}

pub struct BitcoinP2PConfig {
    pub network: Network,
    // This node's identifier on the network (random)
    pub nonce: u64,
    // height of the blockchain tree trunk
    pub height: AtomicUsize,
    // This node's human readable type identification
    pub user_agent: String,
    // this node's maximum protocol version
    pub max_protocol_version: u32,
    // serving others
    pub server: bool,
}

struct PassThroughBufferReader<'a> {
    buffer: &'a mut Buffer
}

impl<'a> io::Read for PassThroughBufferReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.buffer.read(buf)
    }
}

impl P2PConfig<NetworkMessage, RawNetworkMessage> for BitcoinP2PConfig {
    // compile this node's version message for outgoing connections
    fn version (&self, remote: &SocketAddr, max_protocol_version: u32) -> NetworkMessage {
        // now in unix time
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;

        let services = if !self.server {
            0
        } else {
            SERVICE_BLOCKS + SERVICE_WITNESS +
                // announce that this node is capable of serving BIP157 messages
                SERVICE_FILTERS
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
            relay: true,
        })
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }

    fn magic(&self) -> u32 {
        self.network.magic()
    }

    fn user_agent(&self) -> &str {
        self.user_agent.as_str()
    }

    fn get_height(&self) -> u32 {
        self.height.load(Ordering::Relaxed) as u32
    }

    fn set_height(&self, height: u32) {
        self.height.store (height as usize, Ordering::Relaxed)
    }

    fn max_protocol_version(&self) -> u32 {
        self.max_protocol_version
    }

    fn min_protocol_version(&self) -> u32 {
        70001
    }


    fn verack(&self) -> NetworkMessage {
        NetworkMessage::Verack
    }

    fn wrap(&self, m: NetworkMessage) -> RawNetworkMessage {
        RawNetworkMessage{magic: self.network.magic(), payload: m}
    }

    fn unwrap(&self, e: RawNetworkMessage) -> Result<NetworkMessage, io::Error> {
        Ok(e.payload)
    }

    // encode a message in Bitcoin's wire format extending the given buffer
    fn encode(&self, item: &RawNetworkMessage, dst: &mut Buffer) -> Result<(), io::Error> {
        dst.write_all(serialize(item).as_slice())
    }

    // decode a message from the buffer if possible
    fn decode(&self, src: &mut Buffer) -> Result<Option<RawNetworkMessage>, io::Error> {
        // attempt to decode
        let passthrough = PassThroughBufferReader{buffer: src};
        let decode: Result<RawNetworkMessage, encode::Error> =
            Decodable::consensus_decode(passthrough);

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
                    error!("{:?}", e);
                    src.commit();
                    return Err(e);
                }
            },
            Err(e) => {
                error!("{:?}", e);
                src.commit();
                Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}

/// The P2P network layer
pub struct P2P<Message: Version + Send + Sync + Clone + 'static,
    Envelope: Command + Send + Sync + 'static,
    Config: P2PConfig<Message, Envelope> + Send + Sync + 'static> {
    // sender to the dispatcher of incoming messages
    dispatcher: PeerMessageSender<Message>,
    // network specific conf
    pub config: Config,
    // The collection of connected peers
    peers: Arc<RwLock<PeerMap<Message>>>,
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
    e: PhantomData<Envelope>
}

impl<Message: Version + Send + Sync + Clone,
    Envelope: Command + Send + Sync,
    Config: P2PConfig<Message, Envelope> + Send + Sync> P2P<Message, Envelope, Config> {
    /// create a new P2P network controller
    pub fn new(config: Config, dispatcher: PeerMessageSender<Message>, back_pressure: usize) -> (Arc<P2P<Message, Envelope, Config>>, P2PControlSender<Message>) {
        let (control_sender, control_receiver) = mpsc::channel();

        let peers = Arc::new(RwLock::new(PeerMap::new()));

        let p2p = Arc::new(P2P {
            dispatcher,
            config,
            peers: peers.clone(),
            poll: Arc::new(Poll::new().unwrap()),
            next_peer_id: AtomicUsize::new(0),
            waker: Arc::new(Mutex::new(HashMap::new())),
            listener: Arc::new(Mutex::new(HashMap::new())),
            e: PhantomData{}
        });

        let p2p2 = p2p.clone();

        thread::Builder::new().name("p2pcntrl".to_string()).spawn(move || p2p2.control_loop(control_receiver)).unwrap();

        (p2p, P2PControlSender::new(control_sender, peers, back_pressure))
    }

    pub fn connected_peers (&self) -> Vec<SocketAddr> {
        self.peers.read().unwrap().values()
            .filter_map(|peer|
                if let Ok(a) = peer.lock().unwrap().stream.peer_addr() {
                    Some(a)
                } else {None}).collect()
    }

    pub fn n_connected_peers (&self) -> usize {
        self.peers.read().unwrap().len()
    }

    fn control_loop (&self, receiver: P2PControlReceiver<Message>) {
        while let Ok(control) = receiver.recv() {
            match control {
                P2PControl::Ban(peer_id, score) => {
                    self.ban(peer_id, score);
                },
                P2PControl::Disconnect(peer_id) => {
                    self.disconnect(peer_id, false);
                },
                P2PControl::Height(height) => {
                    self.config.set_height(height);
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
    pub fn add_peer (&self, network: &'static str, source: PeerSource) -> impl Future<Output=Result<SocketAddr, Error>> + Send {
        // new token, never re-using previously connected peer's id
        // so log messages are easier to follow
        let token = Token(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        let pid = PeerId{network, token};

        let peers = self.peers.clone();
        let peers2 = self.peers.clone();
        let waker = self.waker.clone();

        self.connecting(pid, source)
            .map_err(move |e| {
                let mut peers = peers2.write().unwrap();
                if let Some(peer) = peers.remove(&pid) {
                    peer.lock().unwrap().stream.shutdown(Shutdown::Both).unwrap_or(());
                }
                e
            })
            .and_then (move |addr| {
            future::poll_fn(move |ctx| {
                if peers.read().unwrap().get(&pid).is_some() {
                    waker.lock().unwrap().insert(pid, ctx.waker().clone());
                    Async::Pending
                } else {
                    debug!("finished orderly peer={}", pid);
                    Async::Ready(Ok(addr))
                }
            })
        })
    }

    fn connecting(&self, pid: PeerId, source: PeerSource) -> impl Future<Output=Result<SocketAddr, Error>> + Send {


        let version = self.config.version(
            &SocketAddr::from_str("127.0.0.1:8333").unwrap(), // TODO wrong address
            self.config.max_protocol_version());
        let peers = self.peers.clone();
        let peers2 = self.peers.clone();
        let poll = self.poll.clone();
        let waker = self.waker.clone();

        future::poll_fn(move |_| {
            match Self::connect(version.clone(), peers.clone(), poll.clone(), pid, source.clone()) {
                Ok(addr) => Async::Ready(Ok(addr)),
                Err(e) => { Async::Ready(Err(e)) }
            }
        }).and_then(move |addr| {
            use futures_timer::TryFutureExt;

            future::poll_fn(move |ctx|
                if let Some(peer) = peers2.read().unwrap().get(&pid) {
                    // return pid if peer is connected (handshake perfect)
                    if peer.lock().unwrap().connected {
                        trace!("woke up to handshake");
                        Async::Ready(Ok(addr))
                    } else {
                        waker.lock().unwrap().insert(pid, ctx.waker().clone());
                        Async::Pending
                    }
                } else {
                    // rejected or failed handshake
                    Async::Ready(Err(Error::Handshake))
                }
            ).timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
        })
    }

    // initiate connection to peer
    fn connect(version: Message, peers: Arc<RwLock<PeerMap<Message>>>, poll: Arc<Poll>, pid: PeerId, source: PeerSource) -> Result<SocketAddr, Error> {
        let outgoing;
        let addr;
        let stream;
        match source {
            PeerSource::Outgoing(a) => {
                if let PeerSource::Outgoing(a) = source {
                    if peers.read().unwrap().values()
                        .any(|peer|
                            if let Ok(addr) = peer.lock().unwrap().stream.peer_addr() {
                                a.ip() == addr.ip()
                            } else { false }) {
                        debug!("rejecting outgoing connect for a peer already connected");
                        return Err(Error::Handshake);
                    }
                }

                addr = a;
                outgoing = true;
                info!("trying outgoing connect to {} peer={}", addr, pid);
                stream = TcpStream::connect(&addr)?;
            },
            PeerSource::Incoming(listener) => {
                let (s, a) = listener.accept()?;
                if peers.read().unwrap().values()
                    .any(|peer|
                        if let Ok(addr) = peer.lock().unwrap().stream.peer_addr() {
                            a.ip() == addr.ip()
                        } else { false }) {
                    debug!("rejecting incoming connect from a peer already connected");
                    s.shutdown(Shutdown::Both).unwrap_or(());
                    return Err(Error::Handshake);
                }
                addr = a;
                stream = s;
                info!("trying incoming connect to {} peer={}", addr, pid);
                outgoing = false;
            }
        };

        // create lock protected peer object
        let peer = Mutex::new(Peer::new(pid, stream, poll.clone(), outgoing)?);

        let mut peers = peers.write().unwrap();

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
            peers.get(&pid).unwrap().lock().unwrap().send(version)?;
        }

        Ok(addr)
    }

    fn disconnect (&self, pid: PeerId, banned: bool) {
        self.dispatcher.send(PeerMessage::Disconnected(pid, banned));
        {
            // remove from peers before waking up, so disconnect is recognized
            let mut peers = self.peers.write().unwrap();
            if let Some(peer) = peers.remove(&pid) {
                peer.lock().unwrap().stream.shutdown(Shutdown::Both).unwrap_or(());
            }
        }
        {
            let mut wakers = self.waker.lock().unwrap();
            if let Some(waker) = wakers.remove(&pid) {
                debug!("waking for disconnect peer={}", pid);
                waker.wake();
            }
        }
    }

    fn connected(&self, pid: PeerId, address: Option<SocketAddr>) {
        self.dispatcher.send(PeerMessage::Connected(pid, address));
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
            debug!("ban peer={}", pid);
            self.disconnect(pid, true);
        }
    }

    fn event_processor (&self, event: Event, pid: PeerId, needed_services: u64, iobuf: &mut [u8]) -> Result<(), Error> {
        let readiness = UnixReady::from(event.readiness());
        // check for error first
        if readiness.is_hup() || readiness.is_error() {
            info!("left us peer={}", pid);
            self.disconnect(pid, false);
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
                                let raw = self.config.wrap(msg);
                                trace!("next message {} to peer={}", raw.command(), pid);
                                // refill write buffer
                                self.config.encode(&raw, &mut locked_peer.write_buffer)?;
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
                // how to disconnect
                let mut ban = false;
                // new handshake if set
                let mut handshake = false;
                // peer address
                let mut address = None;
                // read lock peer map and retrieve peer
                if let Some(peer) = self.peers.read().unwrap().get(&pid) {
                    // lock the peer from the peer
                    let mut locked_peer = peer.lock().unwrap();
                    // read the peer's socket
                    if let Ok(len) = locked_peer.stream.read(iobuf) {
                        trace!("received {} bytes from peer={}", len, pid);
                        if len == 0 {
                            debug!("read zero length message, disconnecting peer={}", pid);
                            disconnect = true;
                        }
                        // accumulate in a buffer
                        locked_peer.read_buffer.write_all(&iobuf[0..len])?;
                        // extract messages from the buffer
                        while let Some(msg) = self.config.decode(&mut locked_peer.read_buffer)? {
                            trace!("received {} peer={}", msg.command(), pid);
                            if locked_peer.connected {
                                // regular processing after handshake
                                incoming.push(msg);
                            }
                            else {
                                // have to get both version and verack to complete handhsake
                                if !(locked_peer.version.is_some() && locked_peer.got_verack) {
                                    // before handshake complete
                                    if let Ok(msg) = self.config.unwrap(msg) {
                                        if let Some(version) = msg.is_version() {
                                            if locked_peer.version.is_some() {
                                                // repeated version
                                                disconnect = true;
                                                ban = true;
                                                debug!("misbehaving peer, repeated version peer={}", pid);
                                                break;
                                            }
                                            if version.nonce == self.config.nonce() {
                                                // connect to myself
                                                disconnect = true;
                                                ban = true;
                                                debug!("rejecting to connect to myself peer={}", pid);
                                                break;
                                            } else {
                                                if version.version < self.config.min_protocol_version() || (needed_services & version.services) != needed_services {
                                                    debug!("rejecting peer of version {} and services {:b} peer={}", version.version, version.services, pid);
                                                    disconnect = true;
                                                    break;
                                                } else {
                                                    if !locked_peer.outgoing {
                                                        // send own version message to incoming peer
                                                        let addr = locked_peer.stream.peer_addr()?;
                                                        trace!("send version to incoming connection {}", addr);
                                                        // do not show higher version than the peer speaks
                                                        let version = self.config.version(&addr, version.version);
                                                        locked_peer.send(version)?;
                                                    } else {
                                                        // outgoing connects should not be behind this
                                                        if version.start_height < self.config.get_height() {
                                                            debug!("rejecting to connect with height {} peer={}", version.start_height, pid);
                                                            disconnect = true;
                                                            break;
                                                        }
                                                    }
                                                    debug!("accepting peer of version {} and services {:b} peer={}", version.version, version.services, pid);
                                                    // acknowledge version message received
                                                    locked_peer.send(self.config.verack())?;
                                                    // all right, remember this peer
                                                    info!("client {} height: {} peer={}", version.user_agent, version.start_height, pid);
                                                    let mut vm = version.clone();
                                                    // reduce protocol version to our capabilities
                                                    vm.version = min(vm.version, self.config.max_protocol_version());
                                                    locked_peer.version = Some(vm);
                                                }
                                            }
                                        } else if msg.is_verack() {
                                            if locked_peer.got_verack {
                                                // repeated verack
                                                disconnect = true;
                                                ban = true;
                                                debug!("misbehaving peer, repeated version peer={}", pid);
                                                break;
                                            }
                                            trace!("got verack peer={}", pid);
                                            locked_peer.got_verack = true;
                                        } else {
                                            debug!("misbehaving peer unexpected message before handshake peer={}", pid);
                                            // some other message before handshake
                                            disconnect = true;
                                            ban = true;
                                            break;
                                        }
                                        if locked_peer.version.is_some() && locked_peer.got_verack {
                                            locked_peer.connected = true;
                                            handshake = true;
                                            address = if let Ok(addr) = locked_peer.stream.peer_addr() {
                                                Some(addr)
                                            } else {
                                                None
                                            }
                                        }
                                    }
                                    else {
                                        debug!("Ban for malformed message peer={}", pid);
                                        disconnect = true;
                                        ban = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    else {
                        debug!("IO error reading peer={}", pid);
                        disconnect = true;
                    }
                }
                if disconnect {
                    info!("disconnecting peer={}", pid);
                    self.disconnect(pid, ban);
                }
                else {
                    if handshake {
                        info!("handshake peer={}", pid);
                        self.connected (pid, address);
                        if let Some(w) = self.waker.lock().unwrap().remove(&pid) {
                            trace!("waking for handshake");
                            w.wake();
                        }
                    }
                    // process queued incoming messages outside lock
                    // as process could call back to P2P
                    for msg in incoming {
                        trace!("processing {} for peer={}", msg.command(), pid);
                        if let Ok(m) = self.config.unwrap(msg) {
                            self.dispatcher.send(PeerMessage::Incoming(pid, m));
                        }
                        else {
                            debug!("Ban for malformed message peer={}", pid);
                            self.disconnect(pid, true);
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
    pub fn poll_events(&self, network: &'static str, needed_services: u64, spawn: &mut dyn Spawn) {
        // events buffer
        let mut events = Events::with_capacity(EVENT_BUFFER_SIZE);
        // IO buffer
        let mut iobuf = vec!(0u8; IO_BUFFER_SIZE);

        loop {
            // get the next batch of events
            self.poll.poll(&mut events, None).expect("can not poll mio events");

            // iterate over events
            for event in events.iter() {
                // check for listener
                if let Some(server) = self.is_listener(event.token()) {
                    trace!("incoming connection request");
                    spawn.spawn(self.add_peer(network, PeerSource::Incoming(server)).map(|_| ())).expect("can not add peer for incoming connection");
                } else {
                    // construct the id of the peer the event concerns
                    let pid = PeerId { network, token: event.token() };
                    if let Err(error) = self.event_processor(event, pid, needed_services, iobuf.as_mut_slice()) {
                        use std::error::Error;

                        debug!("error {:?} peer={}", error.source(), pid);
                        self.ban(pid, 10);
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
struct Peer<Message> {
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
    pub version: Option<VersionCarrier>,
    // channel into the event processing loop for outgoing messages
    sender: mpsc::Sender<Message>,
    // channel into the event processing loop for outgoing messages
    receiver: mpsc::Receiver<Message>,
    // is registered for write?
    writeable: AtomicBool,
    // connected and handshake complete?
    connected: bool,
    // ban score
    ban: u32,
    // outgoing or incoming connection
    outgoing: bool
}

impl<Message> Peer<Message> {
    /// create a new peer
    pub fn new (pid: PeerId, stream: TcpStream, poll: Arc<Poll>, outgoing: bool) -> Result<Peer<Message>, Error> {
        let (sender, receiver) = mpsc::channel();
        let peer = Peer{pid, poll: poll.clone(), stream, read_buffer: Buffer::new(), write_buffer: Buffer::new(),
            got_verack: false, version: None, sender, receiver, writeable: AtomicBool::new(false),
            connected: false, ban: 0, outgoing };
        Ok(peer)
    }

    // re-register for peer readable events
    fn reregister_read(&self) -> Result<(), Error> {
        if self.writeable.swap(false, Ordering::Acquire) {
            trace!("re-register for read peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::readable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }

    // register for peer readable events
    fn register_read(&self) -> Result<(), Error> {
        trace!("register for read peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::readable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        self.writeable.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// send a message to P2P network
    pub fn send (&self, msg: Message) -> Result<(), Error> {
        // send to outgoing message channel
        self.sender.send(msg).map_err(| _ | Error::Downstream("can not send to peer queue".to_owned()))?;
        // register for writable peer events since we have outgoing message
        self.reregister_write()?;
        Ok(())
    }

    // register for peer writable events
    fn reregister_write(&self) -> Result<(), Error> {
        if !self.writeable.swap(true, Ordering::Acquire) {
            trace!("re-register for write peer={}", self.pid);
            self.poll.reregister(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        }
        Ok(())
    }

    // register for peer writable events
    fn register_write(&self) -> Result<(), Error> {
        trace!("register for write peer={}", self.pid);
        self.poll.register(&self.stream, self.pid.token, Ready::writable() | UnixReady::error() | UnixReady::hup(), PollOpt::level())?;
        self.writeable.store(true, Ordering::Relaxed);
        Ok(())
    }


    // try to receive a message from the outgoing message channel
    fn try_receive (&self) -> Option<Message> {
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
pub struct Buffer {
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

    /// not yet consumed length of the buffer
    pub fn len(&self) -> usize {
        self.chunks.iter().skip(self.pos.0).map(|c| c.len()).sum::<usize>() - self.pos.1
    }

    /// rollback to last commit
    pub fn rollback (&mut self) {
        self.pos = self.checkpoint;
    }

    /// checkpoint and drop already read content
    pub fn commit (&mut self) {
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


