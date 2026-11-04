// Modified by the CortenDesk Server project on 2026-08-10: added the server
// half of the signalling key exchange (`key_exchange_offer` /
// `key_exchange_accept`, and the cipher carried on `TcpSink`). Modified on
// 2026-09-29: device access policy checks on punch hole and relay requests,
// and LAN address reports (`crate::policy`). Modified on 2026-10-08: LAN
// address reports identify the sender by the TCP peer on WebSocket too.
// Modified on 2026-11-01: WebRTC signalling for RustDesk 1.5 clients (offers,
// answers and ICE candidates, `crate::webrtc_signal`). Modified on 2026-11-03:
// connection path tags (`conn_audit_ref`); persistent TCP and WebSocket
// registration for desktop clients and the client address from trusted
// proxies, based on PR #1 by vk2amv. Modified on 2026-11-04:
// `always-use-relay` leaves the relay list alone; the punch request log is
// capped and peer IDs are at most 253 bytes; a key file error stops `hbbs`;
// signalling messages are at most 1 MiB. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

use crate::common::*;
use crate::peer::*;
use crate::policy;
use crate::webrtc_signal::{self, Routes};
use crate::stream_connection::{
    Connection, Registration, HEARTBEAT_INTERVAL, HEARTBEAT_SECONDS, RECEIVE_TIMEOUT, WRITE_TIMEOUT,
};
use hbb_common::{
    allow_err, anyhow::anyhow, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, SplitStream, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{Encrypt, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

/// Versioned so the console can tell our tags from anything else in the field.
const AUDIT_REF_PREFIX: &str = "cd1/";
/// Largest signalling message accepted, on TCP and WebSocket. The largest real
/// ones, online requests for big address books, are a few hundred KB at most.
/// Before, a TCP frame could announce up to 1 GiB and a WebSocket message
/// 64 MiB, all buffered before anything was checked.
const MAX_SIGNAL_MESSAGE: usize = 1024 * 1024;

fn signal_codec() -> BytesCodec {
    let mut codec = BytesCodec::new();
    codec.set_max_packet_length(MAX_SIGNAL_MESSAGE);
    codec
}

fn signal_ws_config() -> tungstenite::protocol::WebSocketConfig {
    tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_SIGNAL_MESSAGE))
        .max_frame_size(Some(MAX_SIGNAL_MESSAGE))
}
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;

/// A plain-TCP sink plus the cipher for it, once the connection has been
/// secured. The connection loop owns this writer; asynchronous replies and
/// heartbeats share its encryption sequence through the outbound queue.
struct TcpSink {
    sink: TcpStreamSink,
    encrypt: Option<Encrypt>,
}

enum Sink {
    Queued(Connection),
    TcpStream(TcpSink),
    Ws(WsSink),
}

enum RouteReply {
    /// No route: the reply takes the ordinary path through `tcp_punch`.
    NoRoute,
    /// The route is over its budget; its connection is being misused.
    Drop,
    Send(Connection),
}

enum Reader {
    Tcp(SplitStream<Framed<TcpStream, BytesCodec>>),
    Ws(SplitStream<tokio_tungstenite::WebSocketStream<TcpStream>>),
}
impl Reader {
    async fn next(&mut self) -> ResultType<Option<BytesMut>> {
        match self {
            Self::Tcp(reader) => Ok(reader.next().await.transpose()?),
            Self::Ws(reader) => loop {
                match reader.next().await {
                    Some(Ok(tungstenite::Message::Binary(bytes))) => {
                        return Ok(Some(BytesMut::from(&bytes[..])))
                    }
                    Some(Ok(tungstenite::Message::Close(_))) | None => return Ok(None),
                    Some(Err(err)) => return Err(err.into()),
                    Some(Ok(_)) => continue,
                }
            },
        }
    }
}
impl Sink {
    /// Whether what is written here is encrypted: a secured TCP connection, or
    /// WebSocket, which clients treat as encrypted by its transport (wss).
    fn is_secure(&self) -> bool {
        match self {
            Sink::TcpStream(s) => s.encrypt.is_some(),
            Sink::Ws(_) => true,
            Sink::Queued(c) => c.is_secure(),
        }
    }
    async fn write(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            Self::TcpStream(s) => {
                let bytes = match s.encrypt.as_mut() {
                    Some(enc) => enc.enc(&bytes),
                    None => bytes,
                };
                timeout(WRITE_TIMEOUT, s.sink.send(bytes.into())).await??;
            }
            Self::Ws(s) => {
                timeout(WRITE_TIMEOUT, s.send(tungstenite::Message::Binary(bytes.into()))).await??;
            }
            Self::Queued(connection) => connection.send(bytes)?,
        }
        Ok(())
    }
    async fn close(&mut self) {
        match self {
            Self::Ws(s) => {
                let _ = timeout(1_000, s.close()).await;
            }
            Self::TcpStream(s) => {
                let _ = timeout(1_000, s.sink.close()).await;
            }
            Self::Queued(connection) => connection.close(),
        }
    }
}

/// One lock per device ID being registered; entries live only while in use.
#[derive(Clone, Default)]
struct RegistrationLocks(Arc<std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>>);

impl RegistrationLocks {
    fn get(&self, id: &str) -> Arc<Mutex<()>> {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(id.to_owned()).or_default().clone()
    }

    /// Hand back a lock from `get`, after its guard is dropped.
    fn release(&self, id: &str, lock: Arc<Mutex<()>>) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // The map's copy and ours: nobody else is waiting.
        if Arc::strong_count(&lock) == 2 {
            map.remove(id);
        }
    }
}

type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<VecDeque<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(VecDeque::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;
/// Records kept for the `punch-requests` command, oldest dropped first.
/// `MAX_PUNCH_REQUESTS`, default 100000; 0 keeps none.
static PUNCH_REQ_MAX: Lazy<usize> =
    Lazy::new(|| get_arg("MAX_PUNCH_REQUESTS").parse().unwrap_or(100_000));

async fn record_punch_req(from_ip: String, to_ip: String, to_id: String) {
    let max = *PUNCH_REQ_MAX;
    if max == 0 {
        return;
    }
    let mut lock = PUNCH_REQS.lock().await;
    let mut dup = false;
    for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
        if e.from_ip == from_ip && e.to_id == to_id {
            if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
            break;
        }
    }
    if !dup {
        while lock.len() >= max {
            lock.pop_front();
        }
        lock.push_back(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id });
    }
}

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Connection>>>,
    /// Controller connections in a WebRTC exchange; see `crate::webrtc_signal`.
    webrtc: Arc<Mutex<Routes<Connection>>>,
    registration_locks: RegistrationLocks,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
    ConsoleListener,
}

impl RendezvousServer {
    pub fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        Self::start_with_bind(None, port, serial, key, rmem)
    }

    #[tokio::main(flavor = "multi_thread")]
    pub async fn start_with_bind(
        bind_addr: Option<IpAddr>,
        port: i32,
        serial: i32,
        key: &str,
        rmem: usize,
    ) -> ResultType<()> {
        init_trusted_proxies()?;
        let (key, sk) = Self::get_server_sk(key)?;
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        let mut socket = create_udp_listener(bind_addr, port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            webrtc: Default::default(),
            registration_locks: Default::default(),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        policy::start();
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(bind_addr, port).await?;
        let mut listener2 = create_tcp_listener(bind_addr, nat_port).await?;
        let mut listener3 = create_tcp_listener(bind_addr, ws_port).await?;
        let mut listener_console = listen_console(bind_addr, nat_port as _).await?;
        log::info!("Listening on tcp/udp {}", listener.local_addr()?);
        log::info!(
            "Listening on tcp {}, extra port for NAT test",
            listener2.local_addr()?
        );
        log::info!("Listening on websocket {}", listener3.local_addr()?);
        let test_addr = get_arg("TEST_HBBS");
        if get_arg("ALWAYS_USE_RELAY").to_uppercase() == "Y" {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut listener_console,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(bind_addr, port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(bind_addr, port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(bind_addr, nat_port).await?;
                    }
                    LoopFailure::ConsoleListener => {
                        drop(listener_console.take());
                        listener_console = listen_console(bind_addr, nat_port as _).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(bind_addr, ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        listener_console: &mut Option<TcpListener>,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => { allow_err!(socket.send(msg.as_ref(), addr).await); }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            if let Err(err) = self.handle_udp(&bytes, addr.into(), socket, key).await {
                                log::error!("udp failure: {}", err);
                                return LoopFailure::UdpSocket;
                            }
                        }
                        Some(Err(err)) => {
                            log::error!("udp failure: {}", err);
                            return LoopFailure::UdpSocket;
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = accept_or_pending(listener_console.as_ref()) => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("console listener.accept failed: {}", err);
                           return LoopFailure::ConsoleListener;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() && rp.id.len() <= MAX_PEER_ID_LEN {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let result = self.register_pk(rk, addr, None).await;
                    send_rk_res(socket, addr, result).await?;
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // UDP PunchHoleRequest is intentionally unsupported.
                    // The supported client path sends PunchHoleRequest over TCP/WS.
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    // UDP PunchHoleSent is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // UDP LocalAddr is intentionally unsupported to avoid UDP reflection/amplification
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn register_pk(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
        connection: Option<&Connection>,
    ) -> register_pk_response::Result {
        if rk.uuid.is_empty() || rk.pk.is_empty() {
            return register_pk_response::Result::INVALID_ID_FORMAT;
        }
        if rk.id.len() < 6 || rk.id.len() > MAX_PEER_ID_LEN {
            return UUID_MISMATCH;
        }
        // One registration per ID at a time, so two cannot both claim an
        // empty identity. Other IDs are not held up. The UDP loop never waits:
        // if this ID is being registered elsewhere it answers TOO_FREQUENT and
        // the client retries.
        let lock = self.registration_locks.get(&rk.id);
        let guard = if connection.is_some() {
            lock.clone().lock_owned().await
        } else {
            match lock.clone().try_lock_owned() {
                Ok(guard) => guard,
                Err(_) => {
                    self.registration_locks.release(&rk.id, lock);
                    return TOO_FREQUENT;
                }
            }
        };
        let id = rk.id.clone();
        let result = self.register_pk_locked(rk, addr, connection).await;
        drop(guard);
        self.registration_locks.release(&id, lock);
        result
    }

    async fn register_pk_locked(
        &mut self,
        rk: RegisterPk,
        addr: SocketAddr,
        connection: Option<&Connection>,
    ) -> register_pk_response::Result {
        let id = rk.id;
        let ip = addr.ip().to_string();
        if !self.check_ip_blocker(&ip, &id).await {
            return TOO_FREQUENT;
        }
        let peer = self.pm.get_or(&id).await;
        let (changed, ip_changed) = {
            let peer = peer.read().await;
            if peer.uuid.is_empty() {
                (true, false)
            } else {
                if peer.uuid == rk.uuid {
                    if peer.info.ip != ip && peer.pk != rk.pk {
                        log::warn!(
                            "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                            id,
                            ip,
                            rk.pk,
                            peer.info.ip,
                            peer.pk,
                        );
                        drop(peer);
                        return UUID_MISMATCH;
                    }
                } else {
                    log::warn!(
                        "Peer {} uuid mismatch: {:?} vs {:?}",
                        id,
                        rk.uuid,
                        peer.uuid
                    );
                    drop(peer);
                    return UUID_MISMATCH;
                }
                let ip_changed = peer.info.ip != ip;
                (
                    peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                    ip_changed,
                )
            }
        };
        let mut req_pk = peer.read().await.reg_pk;
        if req_pk.1.elapsed().as_secs() > 6 {
            req_pk.0 = 0;
        } else if req_pk.0 > 2 {
            return TOO_FREQUENT;
        }
        req_pk.0 += 1;
        req_pk.1 = Instant::now();
        peer.write().await.reg_pk = req_pk;
        if ip_changed {
            let mut lock = IP_CHANGES.lock().await;
            if let Some((tm, ips)) = lock.get_mut(&id) {
                if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                    *tm = Instant::now();
                    ips.clear();
                    ips.insert(ip.clone(), 1);
                } else if let Some(v) = ips.get_mut(&ip) {
                    *v += 1;
                } else {
                    ips.insert(ip.clone(), 1);
                }
            } else {
                lock.insert(
                    id.clone(),
                    (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                );
            }
        }
        policy::note_registration(&id, addr.ip());
        if changed {
            let result = self
                .pm
                .update_pk(id.clone(), peer.clone(), addr, rk.uuid, rk.pk, ip)
                .await;
            if result != register_pk_response::Result::OK {
                return result;
            }
        }
        let mut peer = peer.write().await;
        if let Some(connection) = connection {
            if connection.is_closed() {
                return register_pk_response::Result::SERVER_ERROR;
            }
            if let Some(old) = peer.stream.take() {
                if old.connection.id != connection.id {
                    old.connection.close();
                }
            }
            peer.stream = Some(Registration {
                connection: connection.clone(),
                last_seen: Instant::now(),
            });
        } else {
            peer.socket_addr = addr;
            peer.last_reg_time = Instant::now();
        }
        register_pk_response::Result::OK
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        peer_ip: IpAddr,
        key: &str,
        ws: bool,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(mut ph)) => {
                    Self::expect_reply(sink);
                    // A WebRTC offer carries every interface address of the
                    // controller, and the answer and candidates sent back carry
                    // the device's. 1.5 clients only offer on an encrypted
                    // connection; hold any other client to the same.
                    if !ph.webrtc_sdp_offer.is_empty() {
                        let secure = sink.as_ref().map_or(false, |s| s.is_secure());
                        if !secure || ph.webrtc_sdp_offer.len() > webrtc_signal::MAX_SDP_LEN {
                            log::debug!("Dropped a WebRTC offer from {:?}: not encrypted or too long", addr);
                            ph.webrtc_sdp_offer.clear();
                        }
                    }
                    allow_err!(
                        self.handle_tcp_punch_hole_request(addr, peer_ip, ph, key, ws)
                            .await
                    );
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    Self::expect_reply(sink);
                    if let Err(reason) = policy::check_initiator(&rf.token, peer_ip, &rf.id)
                        .and_then(|_| policy::check_target(&rf.id))
                    {
                        log::info!(
                            "Policy: refused relay from {} to {}: {}",
                            peer_ip,
                            rf.id,
                            reason
                        );
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_relay_response(RelayResponse {
                            refuse_reason: reason.to_owned(),
                            ..Default::default()
                        });
                        allow_err!(self.send_to_tcp_sync(msg_out, addr).await);
                        return true;
                    }
                    {
                        let target = rf.id.clone();
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        rf.controlled_context = Self::audit_context("relay");
                        msg_out.set_request_relay(rf);
                        allow_err!(self.send_to_peer(&target, msg_out).await);
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    rr.webrtc_sdp_answer = Self::checked_answer(std::mem::take(&mut rr.webrtc_sdp_answer));
                    if !rr.webrtc_sdp_answer.is_empty() {
                        log::info!("WebRTC answer with relay from {} to {}", rr.id(), addr_b);
                    }
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    // The TCP peer, not `addr`: on WebSocket `addr` comes from
                    // X-Real-IP / X-Forwarded-For, which any client can set.
                    policy::note_local_addr(&la.id, AddrMangle::decode(&la.local_addr), peer_ip);
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                }
                Some(rendezvous_message::Union::IceCandidate(ice)) => {
                    self.handle_ice_candidate(ice, addr).await;
                    // Candidates trickle in on the same connection.
                    return true;
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    let connection = match sink.as_ref() {
                        Some(Sink::Queued(connection)) => connection.clone(),
                        _ => return false,
                    };
                    let res = self.register_pk(rk, addr, Some(&connection)).await;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        keep_alive: HEARTBEAT_SECONDS,
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                    return true;
                }
                Some(rendezvous_message::Union::OnlineRequest(request)) => {
                    let mut response = RendezvousMessage::new();
                    response.set_online_response(OnlineResponse {
                        states: self.online_states(request.peers).await.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, response).await;
                }
                _ => {}
            }
        }
        false
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
                policy::note_registration(&id, ip);
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        if !phs.webrtc_sdp_answer.is_empty() {
            log::info!("WebRTC answer from {} to {}", phs.id, addr_a);
        }
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: phs.relay_server.clone(),
            webrtc_sdp_answer: Self::checked_answer(phs.webrtc_sdp_answer),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if self
            .tcp_punch
            .lock()
            .await
            .contains_key(&try_into_v4(addr_a))
        {
            self.send_to_tcp_sync(msg_out, addr_a).await?;
        } else if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: la.relay_server,
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if self
            .tcp_punch
            .lock()
            .await
            .contains_key(&try_into_v4(addr_a))
        {
            self.send_to_tcp_sync(msg_out, addr_a).await?;
        } else if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        peer_ip: IpAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        let webrtc_offer = std::mem::take(&mut ph.webrtc_sdp_offer);
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        if ph.id.len() > MAX_PEER_ID_LEN {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        if let Err(reason) = policy::check_initiator(&ph.token, peer_ip, &ph.id) {
            log::info!("Policy: refused punch from {} to {}: {}", peer_ip, ph.id, reason);
            let refusal =
                Self::punch_refusal(punch_hole_response::Failure::LICENSE_MISMATCH, reason);
            return Ok((refusal, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let endpoint = peer.read().await.endpoint();
            if let Err(reason) = policy::check_target(&id) {
                log::info!("Policy: refused punch from {} to {}: {}", peer_ip, id, reason);
                let refusal =
                    Self::punch_refusal(punch_hole_response::Failure::ID_NOT_EXIST, reason);
                return Ok((refusal, None));
            }
            if endpoint.is_none() {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            let (peer_addr, peer_ws) = match endpoint {
                Some(endpoint) => endpoint,
                None => unreachable!(),
            };
            // record punch hole request (from addr -> peer id/peer_addr)
            record_punch_req(
                try_into_v4(addr).ip().to_string(),
                try_into_v4(peer_addr).ip().to_string(),
                id.clone(),
            )
            .await;

            let mut msg_out = RendezvousMessage::new();
            let peer_is_lan = self.is_lan(peer_addr);
            let is_lan = self.is_lan(addr);
            let mut relay_server = self.get_relay_server(addr.ip(), peer_addr.ip());
            if ws || peer_ws || ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let same_intranet: bool = !ws
                && !peer_ws
                && (peer_is_lan && is_lan || {
                    // Stream connections are keyed v4; UDP peers on a
                    // dual-stack socket may still be v4-mapped.
                    match (try_into_v4(peer_addr), try_into_v4(addr)) {
                        (SocketAddr::V4(a), SocketAddr::V4(b)) => a.ip() == b.ip(),
                        (SocketAddr::V6(a), SocketAddr::V6(b)) => a.ip() == b.ip(),
                        _ => false,
                    }
                });
            let socket_addr = AddrMangle::encode(addr).into();
            if same_intranet {
                log::debug!(
                    "Fetch local addr {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    controlled_context: Self::audit_context("lan"),
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                // Only now, with the request allowed and going to the device,
                // may candidates flow between the two.
                let webrtc_sdp_offer = if !webrtc_offer.is_empty()
                    && self
                        .webrtc
                        .lock()
                        .await
                        .open(try_into_v4(addr), &id, Instant::now())
                {
                    log::info!("WebRTC offer from {} to {}", addr, id);
                    webrtc_offer
                } else {
                    String::new()
                };
                let path = if webrtc_sdp_offer.is_empty() { "punch" } else { "punch-webrtc" };
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    controlled_context: Self::audit_context(path),
                    webrtc_sdp_offer,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_addr)))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    /// A punch hole refusal the client shows as text. `other_failure` is what
    /// clients display (since 1.1.8); `failure` is for anything older.
    fn punch_refusal(
        failure: punch_hole_response::Failure,
        reason: &str,
    ) -> RendezvousMessage {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_punch_hole_response(PunchHoleResponse {
            failure: failure.into(),
            other_failure: reason.to_owned(),
            ..Default::default()
        });
        msg_out
    }

    async fn online_states(&self, peers: Vec<String>) -> BytesMut {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let online = peer.read().await.endpoint().is_some();
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if online {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        states
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let states = self.online_states(peers).await;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        match self.route_reply(addr).await {
            RouteReply::Send(sink) => {
                let routes = self.webrtc.clone();
                tokio::spawn(async move {
                    if !Self::send_to_shared(&sink, msg) {
                        routes.lock().await.close(try_into_v4(addr));
                    }
                });
                return;
            }
            RouteReply::Drop => return,
            RouteReply::NoRoute => {}
        }
        allow_err!(self.send_to_tcp_sync(msg, addr).await);
    }

    async fn send_to_peer(&self, id: &str, msg: RendezvousMessage) -> ResultType<()> {
        let peer = self
            .pm
            .get_in_memory(id)
            .await
            .ok_or_else(|| anyhow!("peer {} is unavailable", id))?;
        let peer = peer.read().await;
        let stream = peer
            .stream
            .as_ref()
            .filter(|s| s.alive())
            .map(|s| s.connection.clone());
        let endpoint = peer.endpoint();
        drop(peer);
        if let Some(connection) = stream {
            connection.send(msg.write_to_bytes()?)
        } else if let Some((addr, _)) = endpoint {
            self.tx.send(Data::Msg(msg.into(), addr))?;
            Ok(())
        } else {
            bail!("peer {} is offline", id)
        }
    }

    /// The request on this connection gets one reply through `tcp_punch`.
    fn expect_reply(sink: &Option<Sink>) {
        if let Some(Sink::Queued(connection)) = sink {
            connection.expect_reply();
        }
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            match msg.write_to_bytes() {
                Ok(bytes) => {
                    allow_err!(sink.write(bytes).await);
                }
                Err(err) => log::error!("Cannot encode signalling response: {}", err),
            }
        }
    }

    /// False when the connection is gone or its queue is full.
    fn send_to_shared(sink: &Connection, msg: RendezvousMessage) -> bool {
        match msg.write_to_bytes() {
            Ok(bytes) => sink.send(bytes).is_ok(),
            Err(_) => false,
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        match self.route_reply(addr).await {
            RouteReply::Send(sink) => {
                if !Self::send_to_shared(&sink, msg) {
                    self.webrtc.lock().await.close(try_into_v4(addr));
                }
                return Ok(());
            }
            RouteReply::Drop => return Ok(()),
            RouteReply::NoRoute => {}
        }
        let connection = self.tcp_punch.lock().await.get(&try_into_v4(addr)).cloned();
        match connection {
            Some(connection) if connection.take_reply() => connection.send(msg.write_to_bytes()?),
            Some(_) => {
                log::debug!("Dropped a reply to {}: none is owed", addr);
                Ok(())
            }
            None => bail!("signalling connection {} is gone", addr),
        }
    }

    /// The connection of a controller in a WebRTC exchange. The first message
    /// for it moves its sink out of `tcp_punch`, where the first reply would
    /// consume it, into the route, where it serves the whole exchange.
    async fn webrtc_sink(&self, addr: SocketAddr) -> Option<Connection> {
        let addr = try_into_v4(addr);
        let mut routes = self.webrtc.lock().await;
        let route = routes.get(addr, Instant::now())?;
        if route.sink.is_none() {
            let sink = self.tcp_punch.lock().await.get(&addr).cloned()?;
            route.sink = Some(sink);
        }
        route.sink.clone()
    }

    /// Where a reply other than a candidate (the answer, a punch or relay
    /// response) goes when its connection has a route. It counts against the
    /// same budget as candidates, so a route cannot queue unbounded writes.
    async fn route_reply(&self, addr: SocketAddr) -> RouteReply {
        let v4 = try_into_v4(addr);
        {
            let mut routes = self.webrtc.lock().await;
            if !routes.contains(v4, Instant::now()) {
                return RouteReply::NoRoute;
            }
            if !routes.allow_to_controller(v4, Instant::now()) {
                return RouteReply::Drop;
            }
        }
        match self.webrtc_sink(addr).await {
            Some(sink) => RouteReply::Send(sink),
            None => RouteReply::NoRoute,
        }
    }

    /// How hbbs set this connection up, for the console's connection log
    /// (issue #130). RustDesk 1.5+ devices echo `conn_audit_ref` back
    /// unchanged in their connection audit; older ones ignore it. The console
    /// reads the part after `cd1/`, and decides relay separately from what
    /// hbbr reports, since a punch hole can still end up relayed.
    fn audit_context(path: &str) -> MessageField<ControlledContext> {
        MessageField::some(ControlledContext {
            conn_audit_ref: format!("{AUDIT_REF_PREFIX}{path}"),
            ..Default::default()
        })
    }

    fn checked_answer(answer: String) -> String {
        if answer.len() > webrtc_signal::MAX_SDP_LEN {
            String::new()
        } else {
            answer
        }
    }

    /// Pass an ICE candidate on: from a controller to the device it is
    /// offering to (`id` set), or from that device back to the controller
    /// (`socket_addr` set). Anything else is dropped.
    async fn handle_ice_candidate(&mut self, ice: IceCandidate, addr: SocketAddr) {
        if ice.candidate.is_empty()
            || ice.candidate.len() > webrtc_signal::MAX_CANDIDATE_LEN
            || ice.session_key.len() > webrtc_signal::MAX_SESSION_KEY_LEN
        {
            return;
        }
        let now = Instant::now();
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_ice_candidate(IceCandidate {
            session_key: ice.session_key,
            candidate: ice.candidate,
            ..Default::default()
        });
        if !ice.id.is_empty() {
            let allowed = self
                .webrtc
                .lock()
                .await
                .allow_to_peer(try_into_v4(addr), &ice.id, now);
            if !allowed {
                return;
            }
            allow_err!(self.send_to_peer(&ice.id, msg_out).await);
        } else if !ice.socket_addr.is_empty() {
            let addr_a = try_into_v4(AddrMangle::decode(&ice.socket_addr));
            let allowed = self.webrtc.lock().await.allow_to_controller(addr_a, now);
            if !allowed {
                return;
            }
            if let Some(sink) = self.webrtc_sink(addr_a).await {
                if !Self::send_to_shared(&sink, msg_out) {
                    self.webrtc.lock().await.close(addr_a);
                }
            }
        }
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        peer_ip: IpAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let target = ph.id.clone();
        let (msg, to_addr) = self
            .handle_punch_hole_request(addr, peer_ip, ph, key, ws)
            .await?;
        if to_addr.is_some() {
            self.send_to_peer(&target, msg).await?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self
            .handle_punch_hole_request(addr, addr.ip(), ph, key, false)
            .await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur) [Y|N]",
                    "test-geo(tg) <ip1> <ip2>",
                    "policy(pol)"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("policy" | "pol") => {
                res = policy::describe();
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let mut stream = FramedStream::from(stream, addr);
        *stream.codec_mut() = signal_codec();
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        // The client address: the TCP peer, or on WebSocket the address a
        // trusted reverse proxy names. Registration, rate limits and the
        // access policy all use this one address.
        let mut effective_addr = try_into_v4(addr);
        let (mut writer, mut reader, mut exchange_sk) = if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let callback = |request: &Request, response: Response| {
                effective_addr.set_ip(client_ip(addr.ip(), request.headers()));
                Ok(response)
            };
            let stream = timeout(
                WRITE_TIMEOUT,
                tokio_tungstenite::accept_hdr_async_with_config(
                    stream,
                    callback,
                    Some(signal_ws_config()),
                ),
            )
            .await??;
            let (tx, rx) = stream.split();
            (Sink::Ws(tx), Reader::Ws(rx), None)
        } else {
            let (tx, rx) = Framed::new(stream, signal_codec()).split();
            let mut sink = TcpSink {
                sink: tx,
                encrypt: None,
            };
            let exchange = timeout(
                WRITE_TIMEOUT,
                Self::key_exchange_offer(self.inner.sk.as_ref(), &mut sink),
            )
            .await?;
            (Sink::TcpStream(sink), Reader::Tcp(rx), exchange)
        };
        let peer_ip = effective_addr.ip();
        // Keep the real client IP for validation, but never key a proxy session
        // by IP:0. Reserve a nonzero address token for its entire lifetime.
        let (connection, mut outbound, mut cancelled) = {
            let mut connections = self.tcp_punch.lock().await;
            let mut token = effective_addr;
            if ws {
                let start = token.port().max(1);
                token.set_port(start);
                while connections.contains_key(&token) {
                    token.set_port(if token.port() == u16::MAX {
                        1
                    } else {
                        token.port() + 1
                    });
                    if token.port() == start {
                        bail!("no free WebSocket correlation address");
                    }
                }
            } else if connections.contains_key(&token) {
                bail!("duplicate signalling endpoint {}", token);
            }
            let (connection, rx, stop) = Connection::new(token, ws);
            connections.insert(token, connection.clone());
            (connection, rx, stop)
        };
        if ws {
            connection.set_secure();
        }
        let mut sink = Some(Sink::Queued(connection.clone()));
        let mut bound: Option<String> = None;
        let mut decrypt: Option<Encrypt> = None;
        let mut last_received = Instant::now();
        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        heartbeat.tick().await;
        let result: ResultType<()> = async {
            loop {
                tokio::select! {
                    _ = cancelled.changed() => break,
                    bytes = outbound.recv() => {
                        match bytes { Some(bytes) => writer.write(bytes).await?, None => break }
                    }
                    _ = tokio::time::sleep_until((last_received + RECEIVE_TIMEOUT).into()) => {
                        bail!("signalling receive timeout");
                    }
                    _ = heartbeat.tick() => {
                        if bound.is_some() { writer.write(Vec::new()).await?; }
                    }
                    received = reader.next() => {
                        let mut bytes = match received? { Some(bytes) => bytes, None => break };
                        if let Some(dec) = decrypt.as_mut() {
                            dec.dec(&mut bytes)?;
                        } else if let Some(secret) = exchange_sk.as_ref() {
                            match Self::key_exchange_accept(&bytes, secret) {
                                Some(Ok(key)) => {
                                    decrypt = Some(Encrypt::new(key.clone()));
                                    if let Sink::TcpStream(sink) = &mut writer { sink.encrypt = Some(Encrypt::new(key)); }
                                    connection.set_secure();
                                    exchange_sk = None;
                                    continue;
                                }
                                Some(Err(err)) => return Err(err),
                                None => exchange_sk = None,
                            }
                        }
                        if connection.is_closed() { break; }
                        if bytes.is_empty() {
                            // Only an authenticated registration can refresh presence.
                            if let Some(id) = bound.as_ref() {
                                if !self.touch_stream(id, connection.id).await { break; }
                                last_received = Instant::now();
                            }
                            continue;
                        }
                        let message = RendezvousMessage::parse_from_bytes(&bytes)?;
                        let registering = match message.union {
                            Some(rendezvous_message::Union::RegisterPk(ref rk)) => Some(rk.id.clone()),
                            _ => None,
                        };
                        // A stream cannot silently change the device it represents.
                        if let (Some(old), Some(new)) = (&bound, &registering) {
                            if old != new { bail!("registered stream cannot change device ID"); }
                        }
                        let keep = self.handle_tcp(&bytes, &mut sink, connection.addr, peer_ip, key, ws).await;
                        if let Some(id) = registering {
                            if let Some(peer) = self.pm.get_in_memory(&id).await {
                                if peer.read().await.stream.as_ref().map(|s| s.connection.id) == Some(connection.id) {
                                    log::debug!("Registered stream id={} connection={} ws={}", id, connection.id, ws);
                                    bound = Some(id);
                                }
                            }
                        }
                        if let Some(id) = &bound {
                            if !self.touch_stream(id, connection.id).await { break; }
                        }
                        last_received = Instant::now();
                        // Flush responses in order before completing a short request.
                        for _ in 0..64 {
                            match outbound.try_recv() { Ok(bytes) => writer.write(bytes).await?, Err(_) => break }
                        }
                        if !keep && bound.is_none() { break; }
                    }
                }
            }
            Ok(())
        }.await;
        connection.close();
        if let Some(id) = bound {
            if let Some(peer) = self.pm.get_in_memory(&id).await {
                let mut peer = peer.write().await;
                if peer.stream.as_ref().map(|s| s.connection.id) == Some(connection.id) {
                    peer.stream = None;
                }
            }
        }
        {
            let mut connections = self.tcp_punch.lock().await;
            if connections.get(&connection.addr).map(|c| c.id) == Some(connection.id) {
                connections.remove(&connection.addr);
            }
        }
        {
            self.webrtc.lock().await.close(connection.addr);
        }
        writer.close().await;
        log::debug!(
            "Tcp connection from {:?} closed (connection={})",
            effective_addr,
            connection.id
        );
        result
    }

    async fn touch_stream(&self, id: &str, connection_id: u64) -> bool {
        if let Some(peer) = self.pm.get_in_memory(id).await {
            let mut peer = peer.write().await;
            if let Some(stream) = peer.stream.as_mut() {
                if stream.connection.id == connection_id && !stream.connection.is_closed() {
                    stream.last_seen = Instant::now();
                    // A stream registers once; its heartbeats keep the
                    // policy's address match fresh, as UDP RegisterPeer does.
                    policy::note_registration(id, stream.connection.addr.ip());
                    return true;
                }
            }
        }
        false
    }

    /// Server half of the signalling handshake, step 1: hand the client a
    /// throwaway public key signed with the server key it already trusts.
    ///
    /// Sent unprompted on every plain-TCP connection, because that is what the
    /// client waits for. Clients that do not encrypt signalling skip past the
    /// message (they have skipped unknown key-exchange frames since 1.2.0), so
    /// offering it costs them nothing.
    ///
    /// Returns the secret half to keep for step 2, or `None` when there is no
    /// server key pair to sign with — an unsigned offer is worthless, since the
    /// signature is the only thing proving the key came from this server.
    async fn key_exchange_offer(
        sk: Option<&sign::SecretKey>,
        sink: &mut TcpSink,
    ) -> Option<box_::SecretKey> {
        let sk = sk?;
        let (our_pk_b, our_sk_b) = box_::gen_keypair();
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![sign::sign(&our_pk_b.0, sk).into()],
            ..Default::default()
        });
        let bytes = msg_out.write_to_bytes().ok()?;
        sink.sink.send(Bytes::from(bytes)).await.ok()?;
        Some(our_sk_b)
    }

    /// Server half of the signalling handshake, step 2: unseal the symmetric
    /// key the client generated for the rest of this connection.
    ///
    /// `None` means the frame was not a key exchange at all and belongs to the
    /// normal message path; `Some(Err(..))` means it was one and was bad, which
    /// is fatal for the connection.
    fn key_exchange_accept(
        bytes: &[u8],
        our_sk_b: &box_::SecretKey,
    ) -> Option<ResultType<secretbox::Key>> {
        let msg_in = RendezvousMessage::parse_from_bytes(bytes).ok()?;
        match msg_in.union {
            Some(rendezvous_message::Union::KeyExchange(ex)) => {
                if ex.keys.len() != 2 {
                    return Some(Err(anyhow!(
                        "Handshake failed: expected 2 keys, got {}",
                        ex.keys.len()
                    )));
                }
                Some(Encrypt::decode(&ex.keys[1], &ex.keys[0], our_sk_b))
            }
            _ => None,
        }
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> ResultType<(String, Option<sign::SecretKey>)> {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0)?;
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        Ok((key, out_sk))
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        if let Some(network) = &self.inner.mask {
            match addr {
                SocketAddr::V4(v4_socket_addr) => {
                    return network.contains(*v4_socket_addr.ip());
                }

                SocketAddr::V6(v6_socket_addr) => {
                    if let Some(v4_addr) = v6_socket_addr.ip().to_ipv4() {
                        return network.contains(v4_addr);
                    }
                }
            }
        }
        false
    }
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(
    bind_addr: Option<IpAddr>,
    port: i32,
    rmem: usize,
) -> ResultType<FramedSocket> {
    if let Some(bind_addr) = bind_addr {
        let addr = SocketAddr::new(bind_addr, port as _);
        return FramedSocket::new_reuse(&addr, true, rmem).await;
    }
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(bind_addr: Option<IpAddr>, port: i32) -> ResultType<TcpListener> {
    let s = listen_tcp(bind_addr, port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod key_exchange_tests {
    //! Wire-level tests for the signalling handshake.
    //!
    //! The client half here is written to the same algorithm the RustDesk
    //! client uses, so these tests are a compatibility check and not just a
    //! round trip against ourselves: if either side of the exchange drifts,
    //! real clients stop connecting and these tests stop passing together.

    use super::*;
    use hbb_common::tokio::net::TcpListener as TokioTcpListener;

    /// The client half of step 2: verify the server's signed public key, mint a
    /// symmetric key for the connection, and seal it to the server.
    fn client_reply(
        offer: &[u8],
        server_pk: &sign::PublicKey,
    ) -> ResultType<(RendezvousMessage, secretbox::Key)> {
        let msg_in = RendezvousMessage::parse_from_bytes(offer)?;
        let ex = match msg_in.union {
            Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
            _ => bail!("not a key exchange"),
        };
        if ex.keys.len() != 1 {
            bail!("expected 1 key, got {}", ex.keys.len());
        }
        let their_pk_b = sign::verify(&ex.keys[0], server_pk)
            .map_err(|_| anyhow!("signature mismatch in key exchange"))?;
        if their_pk_b.len() != box_::PUBLICKEYBYTES {
            bail!("wrong public key length");
        }
        let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
        pk_.copy_from_slice(&their_pk_b);
        let their_pk_b = box_::PublicKey(pk_);

        let (our_pk_b, our_sk_b) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &their_pk_b, &our_sk_b);

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_key_exchange(KeyExchange {
            keys: vec![Vec::from(our_pk_b.0).into(), sealed.into()],
            ..Default::default()
        });
        Ok((msg_out, key))
    }

    /// Full handshake over a real socket, then an encrypted message each way.
    #[tokio::test]
    async fn secures_a_connection_and_both_directions_decrypt() {
        let (server_pk, server_sk) = sign::gen_keypair();
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            let mut sink = TcpSink {
                sink: a,
                encrypt: None,
            };
            let our_sk_b = RendezvousServer::key_exchange_offer(Some(&server_sk), &mut sink)
                .await
                .expect("offer sent");

            let mut bytes = b.next().await.unwrap().unwrap();
            let key = RendezvousServer::key_exchange_accept(&bytes, &our_sk_b)
                .expect("frame was a key exchange")
                .expect("key exchange accepted");
            let mut decrypt = Encrypt::new(key.clone());
            sink.encrypt = Some(Encrypt::new(key));

            // Server -> client, encrypted.
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_test_nat_response(TestNatResponse {
                port: 4242,
                ..Default::default()
            });
            let mut wrapped = Some(Sink::TcpStream(sink));
            RendezvousServer::send_to_sink(&mut wrapped, msg_out).await;

            // Client -> server, encrypted.
            bytes = b.next().await.unwrap().unwrap();
            decrypt.dec(&mut bytes).expect("decrypts client traffic");
            let msg_in = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => rp.id,
                _ => panic!("unexpected message after handshake"),
            }
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut a, mut b) = Framed::new(stream, BytesCodec::new()).split();
        let offer = b.next().await.unwrap().unwrap();
        let (reply, key) = client_reply(&offer, &server_pk).expect("offer accepted by client");
        a.send(Bytes::from(reply.write_to_bytes().unwrap()))
            .await
            .unwrap();
        let mut cipher = Encrypt::new(key);

        let mut bytes = b.next().await.unwrap().unwrap();
        cipher.dec(&mut bytes).expect("decrypts server traffic");
        let msg_in = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
        match msg_in.union {
            Some(rendezvous_message::Union::TestNatResponse(r)) => assert_eq!(r.port, 4242),
            _ => panic!("unexpected message from server"),
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer(RegisterPeer {
            id: "handshake-test".to_owned(),
            ..Default::default()
        });
        a.send(Bytes::from(cipher.enc(&msg_out.write_to_bytes().unwrap())))
            .await
            .unwrap();

        assert_eq!(server.await.unwrap(), "handshake-test");
    }

    /// A server with no key pair must not offer: the signature is the only
    /// thing that makes the offer meaningful, so an unsigned one is worse than
    /// none at all.
    #[tokio::test]
    async fn no_server_key_means_no_offer() {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (a, _b) = Framed::new(stream, BytesCodec::new()).split();
            let mut sink = TcpSink {
                sink: a,
                encrypt: None,
            };
            RendezvousServer::key_exchange_offer(None, &mut sink)
                .await
                .is_none()
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let (_a, mut b) = Framed::new(stream, BytesCodec::new()).split();
        assert!(server.await.unwrap());
        // Either a clean end of stream or nothing at all — anything else means
        // we put an offer on the wire that no client could verify.
        if let Ok(Some(_)) = timeout(300, b.next()).await {
            panic!("nothing should be sent without a server key");
        }
    }

    /// A client that never encrypts sends a normal message first. That must
    /// read as "not a key exchange" so the connection carries on in plain text
    /// rather than being torn down.
    #[test]
    fn plain_client_traffic_is_not_mistaken_for_a_handshake() {
        let (_, our_sk_b) = box_::gen_keypair();
        let mut msg = RendezvousMessage::new();
        msg.set_punch_hole_request(PunchHoleRequest {
            id: "123456789".to_owned(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        assert!(RendezvousServer::key_exchange_accept(&bytes, &our_sk_b).is_none());
        // Garbage is not a handshake either.
        assert!(RendezvousServer::key_exchange_accept(b"\x01\x02\x03", &our_sk_b).is_none());
    }

    /// A malformed or undecryptable exchange is fatal for that connection —
    /// silently continuing in plain text would let anyone strip the encryption.
    #[test]
    fn a_bad_exchange_is_an_error_not_a_fallback() {
        let (_, our_sk_b) = box_::gen_keypair();

        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange {
            keys: vec![vec![0u8; box_::PUBLICKEYBYTES].into()],
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        assert!(RendezvousServer::key_exchange_accept(&bytes, &our_sk_b)
            .expect("recognised as a key exchange")
            .is_err());

        // Right shape, sealed to somebody else's key.
        let (other_pk_b, other_sk_b) = box_::gen_keypair();
        let (client_pk_b, client_sk_b) = box_::gen_keypair();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(
            &secretbox::gen_key().0,
            &nonce,
            &other_pk_b,
            &client_sk_b,
        );
        let _ = other_sk_b;
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange {
            keys: vec![Vec::from(client_pk_b.0).into(), sealed.into()],
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        assert!(RendezvousServer::key_exchange_accept(&bytes, &our_sk_b)
            .expect("recognised as a key exchange")
            .is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[hbb_common::tokio::test]
    async fn udp_listener_uses_bind_address() {
        let bind_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let socket = create_udp_listener(Some(bind_addr), 0, 0).await.unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), bind_addr);
    }

    #[hbb_common::tokio::test]
    async fn punch_reqs_bounded() {
        let max = *PUNCH_REQ_MAX;
        // 31 ids keep every request just outside the 30-entry dedupe window;
        // at least one request, so MAX_PUNCH_REQUESTS=0 is exercised too.
        for i in 0..(max * 2).max(1) {
            record_punch_req(
                "1.2.3.4".to_owned(),
                "5.6.7.8".to_owned(),
                format!("peer{}", i % 31),
            )
            .await;
        }
        let lock = PUNCH_REQS.lock().await;
        assert_eq!(lock.len(), max);
        if max > 0 {
            // The oldest half is dropped and the newest kept.
            assert_eq!(lock.front().unwrap().to_id, format!("peer{}", max % 31));
            assert_eq!(lock.back().unwrap().to_id, format!("peer{}", (max * 2 - 1) % 31));
        }
    }
}
