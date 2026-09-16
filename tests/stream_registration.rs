//! Wire-level registration and routing tests against isolated hbbs/hbbr processes.
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::Encrypt,
    tokio::{
        self,
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    net::{TcpListener, UdpSocket as StdUdp},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tungstenite::{client::IntoClientRequest, Message};
type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Server {
    child: Child,
    _dir: tempfile::TempDir,
    port: u16,
    key: String,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn free_port() -> u16 {
    loop {
        let main = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = main.local_addr().unwrap().port();
        if port < 1024 || port > 65000 {
            continue;
        }
        if let (Ok(_), Ok(_), Ok(_), Ok(_)) = (
            TcpListener::bind(("127.0.0.1", port - 1)),
            TcpListener::bind(("127.0.0.1", port + 1)),
            TcpListener::bind(("127.0.0.1", port + 2)),
            StdUdp::bind(("127.0.0.1", port)),
        ) {
            return port;
        }
    }
}
impl Server {
    async fn start() -> Self {
        Self::start_with_proxy("127.0.0.0/8,::1/128").await
    }
    async fn start_with_proxy(proxies: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
            .current_dir(dir.path())
            .args([
                "-p",
                &port.to_string(),
                "-k",
                "_",
                "--trusted-proxies",
                proxies,
            ])
            .env_remove("TRUSTED_PROXIES")
            .env_remove("DB_URL")
            .env("TEST_HBBS", "no")
            .env("RUST_LOG", "info")
            .env("TOKIO_WORKER_THREADS", "2")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut server = Self {
            child,
            _dir: dir,
            port,
            key: String::new(),
        };
        for _ in 0..100 {
            assert!(
                server.child.try_wait().unwrap().is_none(),
                "hbbs exited during startup"
            );
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                if let Ok(key) = std::fs::read_to_string(server._dir.path().join("id_ed25519.pub"))
                {
                    server.key = key.trim().to_owned();
                    return server;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("hbbs failed to start");
    }
    async fn ws(&self) -> Ws {
        self.ws_ip("203.0.113.55").await
    }
    async fn ws_ip(&self, ip: &str) -> Ws {
        let mut request = format!("ws://127.0.0.1:{}/ws/id", self.port + 2)
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("X-Real-IP", ip.parse().unwrap());
        connect_async(request).await.unwrap().0
    }
    async fn online(&self, ids: &[&str]) -> Vec<u8> {
        let mut ws = self.ws().await;
        let mut msg = RendezvousMessage::new();
        msg.set_online_request(OnlineRequest {
            peers: ids.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        });
        send(&mut ws, msg).await;
        recv(&mut ws).await.online_response().states.to_vec()
    }
}
fn registration(id: &str, uuid: &[u8]) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: uuid.to_vec().into(),
        pk: vec![7; 32].into(),
        ..Default::default()
    });
    msg
}
async fn send(ws: &mut Ws, msg: RendezvousMessage) {
    ws.send(Message::Binary(msg.write_to_bytes().unwrap()))
        .await
        .unwrap();
}
async fn recv(ws: &mut Ws) -> RendezvousMessage {
    timeout(Duration::from_secs(3), async {
        loop {
            match ws.next().await.expect("WS response").expect("WS read") {
                Message::Binary(bytes) if bytes.is_empty() => {
                    ws.send(Message::Binary(vec![])).await.unwrap();
                }
                Message::Binary(bytes) => {
                    return RendezvousMessage::parse_from_bytes(&bytes).unwrap()
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
    })
    .await
    .expect("response deadline")
}
async fn register(ws: &mut Ws, id: &str) {
    send(ws, registration(id, id.as_bytes())).await;
    let msg = recv(ws).await;
    assert_eq!(
        msg.register_pk_response().result.enum_value(),
        Ok(register_pk_response::Result::OK)
    );
    assert_eq!(msg.register_pk_response().keep_alive, 20);
}
fn punch(id: &str, key: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: key.to_owned(),
        version: "1.4.9".to_owned(),
        ..Default::default()
    });
    msg
}

#[tokio::test]
async fn shared_ip_repeated_routing_reconnect_and_rejected_identity() {
    let server = Server::start().await;
    let mut a = server.ws().await;
    let mut b = server.ws().await;
    register(&mut a, "123456701").await;
    register(&mut b, "123456702").await;
    assert_eq!(server.online(&["123456701", "123456702"]).await, vec![0xc0]);
    let mut rejected = server.ws().await;
    send(&mut rejected, registration("123456701", b"wrong-uuid")).await;
    assert_eq!(
        recv(&mut rejected)
            .await
            .register_pk_response()
            .result
            .enum_value(),
        Ok(register_pk_response::Result::UUID_MISMATCH)
    );
    // Recoverable rejection permits the same client to register its new ID.
    register(&mut rejected, "123456703").await;
    for target in ["123456701", "123456702", "123456701"] {
        let mut initiator = server.ws().await;
        send(&mut initiator, punch(target, &server.key)).await;
        let target_ws = if target == "123456701" {
            &mut a
        } else {
            &mut b
        };
        let forwarded = recv(target_ws).await;
        assert!(forwarded.has_punch_hole());
        assert_eq!(
            forwarded.punch_hole().nat_type.enum_value(),
            Ok(NatType::SYMMETRIC)
        );
        let correlation = forwarded.punch_hole().socket_addr.clone();
        assert_ne!(AddrMangle::decode(&correlation).port(), 0);
        let mut responder = server.ws().await;
        let mut response = RendezvousMessage::new();
        response.set_relay_response(RelayResponse {
            socket_addr: correlation,
            uuid: target.to_owned(),
            ..Default::default()
        });
        send(&mut responder, response).await;
        assert_eq!(recv(&mut initiator).await.relay_response().uuid, target);
    }
    let mut replacement = server.ws().await;
    register(&mut replacement, "123456701").await;
    // Read the old connection's Close, then check cleanup did not remove the new owner.
    let _ = timeout(Duration::from_secs(2), a.next()).await.unwrap();
    drop(a);
    sleep(Duration::from_millis(50)).await;
    assert_eq!(server.online(&["123456701"]).await, vec![0x80]);
    let mut initiator = server.ws().await;
    send(&mut initiator, punch("123456701", &server.key)).await;
    assert!(recv(&mut replacement).await.has_punch_hole());
    replacement.close(None).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    assert_eq!(server.online(&["123456701", "123456702"]).await, vec![0x40]);
}

#[tokio::test]
async fn heartbeat_echo_keeps_idle_registration_alive_and_silent_peer_expires() {
    let server = Server::start().await;
    let mut live = server.ws().await;
    let mut silent = server.ws().await;
    register(&mut live, "123456710").await;
    register(&mut silent, "123456711").await;
    let start = Instant::now();
    let mut beats = 0;
    while start.elapsed() < Duration::from_secs(35) {
        match timeout(Duration::from_secs(12), live.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Binary(bytes) => {
                assert!(bytes.is_empty());
                live.send(Message::Binary(vec![])).await.unwrap();
                beats += 1;
            }
            frame => panic!("heartbeat frame {frame:?}"),
        }
    }
    assert!(beats >= 3);
    assert_eq!(server.online(&["123456710", "123456711"]).await, vec![0x80]);
    let mut initiator = server.ws().await;
    send(&mut initiator, punch("123456710", &server.key)).await;
    assert!(recv(&mut live).await.has_punch_hole());
}

#[tokio::test]
async fn native_udp_presence_survives_stream_disconnect_and_untrusted_headers_are_ignored() {
    let server = Server::start_with_proxy("192.0.2.0/24").await;
    let mut ws = server.ws_ip("2001:db8::55").await;
    register(&mut ws, "123456720").await;
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(
        &registration("123456720", b"123456720")
            .write_to_bytes()
            .unwrap(),
        ("127.0.0.1", server.port),
    )
    .await
    .unwrap();
    let mut buf = [0; 1024];
    let (n, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        RendezvousMessage::parse_from_bytes(&buf[..n])
            .unwrap()
            .register_pk_response()
            .result
            .enum_value(),
        Ok(register_pk_response::Result::OK)
    );
    // A UDP heartbeat cannot divert delivery away from a still-active stream.
    let mut initiator = server.ws().await;
    send(&mut initiator, punch("123456720", &server.key)).await;
    let forwarded = recv(&mut ws).await;
    assert!(AddrMangle::decode(&forwarded.punch_hole().socket_addr)
        .ip()
        .is_loopback());
    ws.close(None).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    assert_eq!(server.online(&["123456720"]).await, vec![0x80]);
    send(&mut initiator, punch("123456720", &server.key)).await;
    let (n, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(RendezvousMessage::parse_from_bytes(&buf[..n])
        .unwrap()
        .has_punch_hole());
}

struct Native {
    framed: Framed<TcpStream, BytesCodec>,
    cipher: Option<Encrypt>,
}
impl Native {
    async fn connect(server: &Server, encrypted: bool) -> Self {
        let stream = TcpStream::connect(("127.0.0.1", server.port))
            .await
            .unwrap();
        let mut framed = Framed::new(stream, BytesCodec::new());
        let offer = framed.next().await.unwrap().unwrap();
        let mut cipher = None;
        if encrypted {
            let message = RendezvousMessage::parse_from_bytes(&offer).unwrap();
            let key = base64::decode(&server.key).unwrap();
            let public = sign::PublicKey::from_slice(&key).unwrap();
            let ephemeral = sign::verify(&message.key_exchange().keys[0], &public).unwrap();
            let ephemeral = box_::PublicKey::from_slice(&ephemeral).unwrap();
            let (pk, sk) = box_::gen_keypair();
            let symmetric = secretbox::gen_key();
            let sealed = box_::seal(&symmetric.0, &box_::Nonce([0; 24]), &ephemeral, &sk);
            let mut msg = RendezvousMessage::new();
            msg.set_key_exchange(KeyExchange {
                keys: vec![pk.0.to_vec().into(), sealed.into()],
                ..Default::default()
            });
            framed
                .send(Bytes::from(msg.write_to_bytes().unwrap()))
                .await
                .unwrap();
            cipher = Some(Encrypt::new(symmetric));
        }
        Self { framed, cipher }
    }
    async fn send(&mut self, msg: RendezvousMessage) {
        let bytes = msg.write_to_bytes().unwrap();
        let bytes = match self.cipher.as_mut() {
            Some(cipher) => cipher.enc(&bytes),
            None => bytes,
        };
        self.framed.send(bytes.into()).await.unwrap();
    }
    async fn raw(&mut self) -> Vec<u8> {
        let mut bytes = timeout(Duration::from_secs(12), self.framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Some(cipher) = self.cipher.as_mut() {
            cipher.dec(&mut bytes).unwrap();
        }
        bytes.to_vec()
    }
    async fn recv(&mut self) -> RendezvousMessage {
        loop {
            let bytes = self.raw().await;
            if bytes.is_empty() {
                // RustDesk's stream heartbeat reply bypasses signalling encryption.
                self.framed.send(Bytes::new()).await.unwrap();
            } else {
                return RendezvousMessage::parse_from_bytes(&bytes).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn native_registration_encryption_heartbeat_and_ws_routing() {
    let server = Server::start().await;
    for encrypted in [false, true] {
        let id = if encrypted { "123456731" } else { "123456730" };
        let mut native = Native::connect(&server, encrypted).await;
        native.send(registration(id, id.as_bytes())).await;
        assert_eq!(
            native
                .recv()
                .await
                .register_pk_response()
                .result
                .enum_value(),
            Ok(register_pk_response::Result::OK)
        );
        let mut initiator = server.ws().await;
        send(&mut initiator, punch(id, &server.key)).await;
        let forwarded = native.recv().await;
        assert!(forwarded.has_punch_hole());
        // Confirm the native cipher remains synchronized across heartbeat replies.
        assert!(native.raw().await.is_empty());
        native.framed.send(Bytes::new()).await.unwrap();
        send(&mut initiator, punch(id, &server.key)).await;
        assert!(native.recv().await.has_punch_hole());
        // An encrypted native initiator can also reach a registered WS device.
        let mut ws_target = server.ws().await;
        let target = if encrypted { "123456733" } else { "123456732" };
        register(&mut ws_target, target).await;
        native.send(punch(target, &server.key)).await;
        let request = recv(&mut ws_target).await;
        assert_eq!(
            request.punch_hole().nat_type.enum_value(),
            Ok(NatType::SYMMETRIC)
        );
        let mut responder = server.ws().await;
        let mut response = RendezvousMessage::new();
        response.set_relay_response(RelayResponse {
            socket_addr: request.punch_hole().socket_addr.clone(),
            uuid: target.into(),
            ..Default::default()
        });
        send(&mut responder, response).await;
        assert_eq!(native.recv().await.relay_response().uuid, target);
    }
}

#[tokio::test]
async fn two_initiators_on_same_forwarded_ipv6_receive_only_their_responses() {
    let server = Server::start().await;
    let mut target = server.ws_ip("2001:db8::25").await;
    register(&mut target, "123456740").await;
    let mut first = server.ws_ip("2001:db8::25").await;
    let mut second = server.ws_ip("2001:db8::25").await;
    send(&mut first, punch("123456740", &server.key)).await;
    let a = recv(&mut target).await.punch_hole().socket_addr.clone();
    send(&mut second, punch("123456740", &server.key)).await;
    let b = recv(&mut target).await.punch_hole().socket_addr.clone();
    assert_ne!(a, b);
    assert_eq!(AddrMangle::decode(&a).ip().to_string(), "2001:db8::25");
    for (addr, uuid) in [(b, "second"), (a, "first")] {
        let mut responder = server.ws().await;
        let mut response = RendezvousMessage::new();
        response.set_relay_response(RelayResponse {
            socket_addr: addr,
            uuid: uuid.into(),
            ..Default::default()
        });
        send(&mut responder, response).await;
    }
    assert_eq!(recv(&mut first).await.relay_response().uuid, "first");
    assert_eq!(recv(&mut second).await.relay_response().uuid, "second");
}

#[tokio::test]
async fn persistence_failure_returns_server_error_without_claiming_identity() {
    use sqlx::Connection as _;
    let server = Server::start().await;
    let path = server._dir.path().join("db_v2.sqlite3");
    let mut db = sqlx::SqliteConnection::connect(path.to_str().unwrap())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER reject_test_insert BEFORE INSERT ON peer BEGIN SELECT RAISE(FAIL, 'test persistence failure'); END")
        .execute(&mut db).await.unwrap();
    let mut ws = server.ws().await;
    send(&mut ws, registration("123456750", b"failed-identity")).await;
    assert_eq!(
        recv(&mut ws)
            .await
            .register_pk_response()
            .result
            .enum_value(),
        Ok(register_pk_response::Result::SERVER_ERROR)
    );
    assert_eq!(server.online(&["123456750"]).await, vec![0]);
    sqlx::query("DROP TRIGGER reject_test_insert")
        .execute(&mut db)
        .await
        .unwrap();
    // A failed insert must not reserve the UUID or mark the peer online.
    register(&mut ws, "123456750").await;
    assert_eq!(server.online(&["123456750"]).await, vec![0x80]);
}

#[tokio::test]
async fn relay_preserves_messages_for_native_ws_and_mixed_pairs() {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir.path())
        .args(["-p", &port.to_string(), "-k", "relay-test-key"])
        .env("RUST_LOG", "info")
        .env("TOKIO_WORKER_THREADS", "2")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server {
        child,
        _dir: dir,
        port,
        key: "relay-test-key".into(),
    };
    for _ in 0..100 {
        assert!(
            server.child.try_wait().unwrap().is_none(),
            "hbbr exited during startup"
        );
        if connect_async(format!("ws://127.0.0.1:{}/ws/relay", port + 2))
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    // hbbr reserves native loopback connections for its management interface.
    // Connect through this machine's non-loopback address to exercise relay data.
    let host = local_ip_address::local_ip().expect("local interface for relay test");
    assert!(
        !host.is_loopback(),
        "relay integration test needs a non-loopback local interface"
    );
    enum Relay {
        Native(Framed<TcpStream, BytesCodec>),
        Ws(Ws),
    }
    impl Relay {
        async fn open(host: std::net::IpAddr, port: u16, ws: bool) -> Self {
            if ws {
                Self::Ws(
                    connect_async(format!(
                        "ws://{}/ws/relay",
                        std::net::SocketAddr::new(host, port + 2)
                    ))
                    .await
                    .unwrap()
                    .0,
                )
            } else {
                Self::Native(Framed::new(
                    TcpStream::connect((host, port)).await.unwrap(),
                    BytesCodec::new(),
                ))
            }
        }
        async fn send(&mut self, bytes: Vec<u8>) {
            match self {
                Self::Native(stream) => stream.send(bytes.into()).await.unwrap(),
                Self::Ws(stream) => stream.send(Message::Binary(bytes)).await.unwrap(),
            }
        }
        async fn recv(&mut self) -> Vec<u8> {
            timeout(Duration::from_secs(5), async {
                match self {
                    Self::Native(stream) => stream.next().await.unwrap().unwrap().to_vec(),
                    Self::Ws(stream) => match stream.next().await.unwrap().unwrap() {
                        Message::Binary(bytes) => bytes,
                        other => panic!("relay frame {other:?}"),
                    },
                }
            })
            .await
            .expect("relay data deadline")
        }
    }
    for (index, (a_ws, b_ws)) in [(false, false), (true, true), (false, true), (true, false)]
        .into_iter()
        .enumerate()
    {
        let mut a = Relay::open(host, port, a_ws).await;
        let mut b = Relay::open(host, port, b_ws).await;
        let mut request = RendezvousMessage::new();
        request.set_request_relay(RequestRelay {
            id: "123456760".into(),
            uuid: format!("pair-{index}"),
            licence_key: server.key.clone(),
            ..Default::default()
        });
        a.send(request.write_to_bytes().unwrap()).await;
        // Ensure A is in the waiting map before B arrives.
        sleep(Duration::from_millis(50)).await;
        b.send(request.write_to_bytes().unwrap()).await;
        for size in [1, 63, 64, 16384, 100000] {
            let payload = vec![0x5a; size];
            a.send(payload.clone()).await;
            assert_eq!(b.recv().await, payload, "A->B modes {a_ws}/{b_ws}");
            let payload = vec![0xa5; size + 3];
            b.send(payload.clone()).await;
            assert_eq!(a.recv().await, payload, "B->A modes {a_ws}/{b_ws}");
        }
    }
}
