//! End-to-end tests of the console device policy against a real hbbs process
//! and a fake console: refused and admitted initiators, refused targets,
//! incoming-only devices, token and web ticket identity, snapshot refresh,
//! outage behaviour, and LAN address reports.
//!
//! Every peer here registers from 127.0.0.1, so the IP match always finds
//! them; the tests pick who registers to decide what the match sees.

use axum::{
    extract::Extension,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
    Router,
};
use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// One port per test: each starts its own hbbs, which also claims port-1
// (admin commands) and port+2 (websocket). Clear of signalling_handshake.rs.
const PORT_OPEN: i32 = 31146;
const PORT_APPROVE: i32 = 31156;
const PORT_TARGET: i32 = 31166;
const PORT_INCOMING: i32 = 31176;
const PORT_TOKEN: i32 = 31186;
const PORT_OUTAGE: i32 = 31196;
const PORT_LAN: i32 = 31206;
const PORT_LAN_WS: i32 = 31216;

const SECRET: &str = "test-link-secret";

const DENY_UNAPPROVED: &str = "This device is not approved on this server";
const DENY_INCOMING_ONLY: &str = "This device is set to incoming only";
const DENY_TARGET: &str = "The remote device is not approved on this server.";

// ---- a fake console ---------------------------------------------------------

#[derive(Default)]
struct Console {
    body: String,
    version: u32,
    fail: bool,
    pulls: usize,
    not_modified: usize,
    reports: Vec<serde_json::Value>,
}

type Shared = Arc<Mutex<Console>>;

fn authorized(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {SECRET}"))
}

async fn policy(Extension(st): Extension<Shared>, headers: HeaderMap) -> (StatusCode, HeaderMap, String) {
    let mut c = st.lock().unwrap();
    let mut out = HeaderMap::new();
    if !authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, out, String::new());
    }
    if c.fail {
        return (StatusCode::INTERNAL_SERVER_ERROR, out, String::new());
    }
    c.pulls += 1;
    let etag = format!("\"v{}\"", c.version);
    out.insert("etag", HeaderValue::from_str(&etag).unwrap());
    if headers.get("if-none-match").and_then(|v| v.to_str().ok()) == Some(etag.as_str()) {
        c.not_modified += 1;
        return (StatusCode::NOT_MODIFIED, out, String::new());
    }
    (StatusCode::OK, out, c.body.clone())
}

async fn local_addrs(Extension(st): Extension<Shared>, headers: HeaderMap, body: String) -> StatusCode {
    if !authorized(&headers) {
        return StatusCode::UNAUTHORIZED;
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    st.lock().unwrap().reports.push(v);
    StatusCode::OK
}

fn set_policy(st: &Shared, body: serde_json::Value) {
    let mut c = st.lock().unwrap();
    c.body = body.to_string();
    c.version += 1;
}

/// Start a fake console on a free port. Returns its URL and its state.
fn start_console(body: serde_json::Value) -> (String, Shared) {
    let st: Shared = Default::default();
    set_policy(&st, body);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/api/server/policy", get(policy))
        .route("/api/server/local-addrs", post(local_addrs))
        .layer(Extension(st.clone()));
    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .ok();
    });
    (url, st)
}

// ---- hbbs -------------------------------------------------------------------

struct Hbbs(Child);

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start hbbs in `dir`, linked to `console` when given. Returns its key.
fn spawn_hbbs(dir: &std::path::Path, port: i32, console: Option<&str>) -> (Hbbs, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env_remove("CORTENDESK_CONSOLE_URL")
        .env_remove("CORTENDESK_SERVER_SECRET")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(url) = console {
        cmd.env("CORTENDESK_CONSOLE_URL", url)
            .env("CORTENDESK_SERVER_SECRET", SECRET)
            .env("CORTENDESK_POLICY_INTERVAL", "1");
    }
    let mut child = cmd.spawn().expect("hbbs starts");
    let stdout = child.stdout.take().expect("stdout piped");
    let (tx, rx) = std::sync::mpsc::channel();
    // Keep draining after the key so a chatty log can never fill the pipe.
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(k) = line.split("Key: ").nth(1) {
                if let Some(tx) = tx.take() {
                    tx.send(k.trim().to_owned()).ok();
                }
            }
        }
    });
    let key = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("hbbs logs its key");
    (Hbbs(child), key)
}

/// Run an hbbs admin command on its loopback port - 1.
async fn admin(port: i32, cmd: &str) -> String {
    let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{}", port - 1)).await else {
        return String::new();
    };
    s.write_all(cmd.as_bytes()).await.ok();
    let mut out = String::new();
    timeout(Duration::from_secs(2), s.read_to_string(&mut out)).await.ok();
    out
}

/// Wait until hbbs reports a policy containing `needle`.
async fn wait_policy(port: i32, needle: &str) {
    let mut last = String::new();
    for _ in 0..100 {
        last = admin(port, "pol").await;
        if last.contains(needle) {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("policy never showed {needle:?}, last: {last:?}");
}

// ---- peers ------------------------------------------------------------------

/// A registered device: its UDP socket is where hbbs forwards requests for it.
struct Peer {
    sock: UdpSocket,
    id: String,
}

impl Peer {
    async fn register(port: i32, id: &str) -> Peer {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: format!("uuid-{id}").into_bytes().into(),
            pk: vec![7u8; 32].into(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        let mut buf = [0u8; 1024];
        for _ in 0..50 {
            sock.send_to(&bytes, format!("127.0.0.1:{port}")).await.ok();
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
                let res = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
                match res.union {
                    Some(rendezvous_message::Union::RegisterPkResponse(r)) => {
                        assert_eq!(
                            r.result.enum_value(),
                            Ok(register_pk_response::Result::OK),
                            "{id} registers"
                        );
                        return Peer { sock, id: id.to_owned() };
                    }
                    other => panic!("unexpected reply to RegisterPk: {other:?}"),
                }
            }
        }
        panic!("hbbs never answered RegisterPk for {id}");
    }

    /// What hbbs forwarded to this peer, if anything, within `ms`. Skips late
    /// answers to a retried registration.
    async fn forwarded(&self, ms: u64) -> Option<RendezvousMessage> {
        let mut buf = [0u8; 1024];
        let deadline = hbb_common::tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            let left = deadline.saturating_duration_since(hbb_common::tokio::time::Instant::now());
            let (n, _) = timeout(left, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
            let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
            if !matches!(msg.union, Some(rendezvous_message::Union::RegisterPkResponse(_))) {
                return Some(msg);
            }
        }
    }
}

type Conn = Framed<TcpStream, BytesCodec>;

async fn connect(port: i32) -> Conn {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(format!("127.0.0.1:{port}")).await {
            return Framed::new(s, BytesCodec::new());
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never accepted a connection on {port}");
}

async fn send(conn: &mut Conn, msg: RendezvousMessage) {
    conn.send(Bytes::from(msg.write_to_bytes().unwrap()))
        .await
        .expect("request sent");
}

/// The next reply that is not the unsolicited key exchange offer.
async fn reply(conn: &mut Conn, ms: u64) -> Option<RendezvousMessage> {
    loop {
        let bytes = match timeout(Duration::from_millis(ms), conn.next()).await {
            Ok(Some(Ok(b))) => b,
            _ => return None,
        };
        let msg = RendezvousMessage::parse_from_bytes(&bytes).expect("reply parses");
        if !matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
            return Some(msg);
        }
    }
}

async fn punch(port: i32, key: &str, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        token: token.to_owned(),
        licence_key: key.to_owned(),
        version: "1.4.3".to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

async fn request_relay(port: i32, target: &str, token: &str) -> Conn {
    let mut conn = connect(port).await;
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: target.to_owned(),
        uuid: "5c8a1d9e-relay-test".to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    send(&mut conn, msg).await;
    conn
}

/// Assert the punch was refused with a message containing `text`.
async fn assert_refused(conn: &mut Conn, text: &str, failure: punch_hole_response::Failure) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
            assert!(ph.socket_addr.is_empty(), "a refusal carries no address");
            assert!(
                ph.other_failure.contains(text),
                "expected {text:?}, got {:?}",
                ph.other_failure
            );
            assert_eq!(ph.failure.enum_value(), Ok(failure));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

async fn assert_relay_refused(conn: &mut Conn, text: &str) {
    match reply(conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::RelayResponse(rr))) => assert!(
            rr.refuse_reason.contains(text),
            "expected {text:?}, got {:?}",
            rr.refuse_reason
        ),
        other => panic!("expected a relay refusal, got {other:?}"),
    }
}

/// Assert hbbs passed the punch on: the target is asked for its local
/// address (both ends share 127.0.0.1) and the initiator is not refused.
async fn assert_forwarded(conn: &mut Conn, target: &Peer) -> FetchLocalAddr {
    let msg = target.forwarded(3000).await;
    let fla = match msg.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::FetchLocalAddr(fla))) => fla,
        other => panic!("{} should have been asked for its local address, got {other:?}", target.id),
    };
    assert!(reply(conn, 300).await.is_none(), "the initiator must not be refused");
    fla
}

fn sha256_hex(s: &str) -> String {
    sha256::hash(s.as_bytes())
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn ticket(expires_in: i64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let signed = format!("cdw1.{}.web-1", now + expires_in);
    let mut st = hmacsha256::State::init(SECRET.as_bytes());
    st.update(signed.as_bytes());
    let sig: String = st.finalize().0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{signed}.{sig}")
}

// ---- tests ------------------------------------------------------------------

/// No console link: hbbs behaves exactly as before, and anyone may connect.
#[tokio::test]
async fn without_a_console_link_nothing_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_OPEN, None);
    wait_policy(PORT_OPEN, "console link off").await;

    let target = Peer::register(PORT_OPEN, "open-target").await;
    let mut conn = punch(PORT_OPEN, &key, &target.id, "").await;
    assert_forwarded(&mut conn, &target).await;
}

/// Approved-only mode: a pending device is refused; approving it in the
/// console lets it through on the next refresh.
#[tokio::test]
async fn pending_initiator_is_refused_until_approved() {
    let (url, console) = start_console(serde_json::json!({
        "mode": "approved", "allow": ["appr-target"], "incoming_only": [], "tokens": {}
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_APPROVE, Some(&url));
    wait_policy(PORT_APPROVE, "mode=approved allow=1").await;

    let target = Peer::register(PORT_APPROVE, "appr-target").await;
    let _initiator = Peer::register(PORT_APPROVE, "appr-pending").await;

    let mut conn = punch(PORT_APPROVE, &key, &target.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;
    let mut conn = request_relay(PORT_APPROVE, &target.id, "").await;
    assert_relay_refused(&mut conn, DENY_UNAPPROVED).await;
    assert!(target.forwarded(300).await.is_none(), "nothing reaches the target");

    // Approved, but signed out: without IP matching nothing identifies it.
    set_policy(&console, serde_json::json!({
        "mode": "approved", "allow": ["appr-target", "appr-pending"], "incoming_only": [], "tokens": {}
    }));
    wait_policy(PORT_APPROVE, "allow=2").await;

    let mut conn = punch(PORT_APPROVE, &key, &target.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;

    // With IP matching on, the registration from this IP identifies it.
    set_policy(&console, serde_json::json!({
        "mode": "approved", "allow": ["appr-target", "appr-pending"], "incoming_only": [], "tokens": {},
        "ip_match": true
    }));
    wait_policy(PORT_APPROVE, "ip_match=true").await;

    let mut conn = punch(PORT_APPROVE, &key, &target.id, "").await;
    assert_forwarded(&mut conn, &target).await;
}

/// Approved-only mode: an approved device cannot reach an unapproved one.
#[tokio::test]
async fn unapproved_target_is_refused() {
    let (url, _console) = start_console(serde_json::json!({
        "mode": "approved", "allow": ["tgt-desk"], "incoming_only": [], "tokens": {},
        "ip_match": true
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_TARGET, Some(&url));
    wait_policy(PORT_TARGET, "mode=approved").await;

    let _desk = Peer::register(PORT_TARGET, "tgt-desk").await;
    let stranger = Peer::register(PORT_TARGET, "tgt-stranger").await;

    let mut conn = punch(PORT_TARGET, &key, &stranger.id, "").await;
    assert_refused(&mut conn, DENY_TARGET, punch_hole_response::Failure::ID_NOT_EXIST).await;
    let mut conn = request_relay(PORT_TARGET, &stranger.id, "").await;
    assert_relay_refused(&mut conn, DENY_TARGET).await;
    assert!(stranger.forwarded(300).await.is_none());
}

/// Incoming-only is enforced in open mode too: the device can be reached but
/// cannot start a session.
#[tokio::test]
async fn incoming_only_device_receives_but_cannot_start() {
    let (url, _console) = start_console(serde_json::json!({
        "mode": "open", "allow": ["io-desk", "io-kiosk"], "incoming_only": ["io-kiosk"], "tokens": {}
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_INCOMING, Some(&url));
    wait_policy(PORT_INCOMING, "mode=open").await;

    let desk = Peer::register(PORT_INCOMING, "io-desk").await;
    let kiosk = Peer::register(PORT_INCOMING, "io-kiosk").await;

    // kiosk -> desk: the only other peer at this IP is the kiosk itself.
    let mut conn = punch(PORT_INCOMING, &key, &desk.id, "").await;
    assert_refused(&mut conn, DENY_INCOMING_ONLY, punch_hole_response::Failure::LICENSE_MISMATCH).await;
    let mut conn = request_relay(PORT_INCOMING, &desk.id, "").await;
    assert_relay_refused(&mut conn, DENY_INCOMING_ONLY).await;

    // desk -> kiosk works.
    let mut conn = punch(PORT_INCOMING, &key, &kiosk.id, "").await;
    assert_forwarded(&mut conn, &kiosk).await;
}

/// A signed-in client is identified by its access token, ahead of the IP
/// match; the console's web client by its signed ticket.
#[tokio::test]
async fn access_token_and_web_ticket_identify_the_initiator() {
    let (url, _console) = start_console(serde_json::json!({
        "mode": "approved",
        "allow": ["tok-target", "tok-approved"],
        "incoming_only": [],
        "tokens": {
            sha256_hex("token-of-approved"): "tok-approved",
            sha256_hex("token-of-pending"): "tok-pending",
        },
        "ip_match": true
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_TOKEN, Some(&url));
    wait_policy(PORT_TOKEN, "tokens=2").await;
    let target = Peer::register(PORT_TOKEN, "tok-target").await;

    // Nobody else is registered here, so without identity: refused.
    let mut conn = punch(PORT_TOKEN, &key, &target.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;

    let mut conn = punch(PORT_TOKEN, &key, &target.id, "token-of-approved").await;
    assert_forwarded(&mut conn, &target).await;

    let mut conn = punch(PORT_TOKEN, &key, &target.id, &ticket(600)).await;
    assert_forwarded(&mut conn, &target).await;
    let mut conn = punch(PORT_TOKEN, &key, &target.id, &ticket(-5)).await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;

    // The token decides even when the IP match would let it through.
    let _approved = Peer::register(PORT_TOKEN, "tok-approved").await;
    let mut conn = punch(PORT_TOKEN, &key, &target.id, "token-of-pending").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;
    let mut conn = punch(PORT_TOKEN, &key, &target.id, "").await;
    assert_forwarded(&mut conn, &target).await;
}

/// The last good policy survives a console outage and a restart; unchanged
/// policy is not downloaded again.
#[tokio::test]
async fn console_outage_keeps_the_last_policy() {
    let (url, console) = start_console(serde_json::json!({
        "mode": "approved", "allow": ["out-target"], "incoming_only": [], "tokens": {}
    }));
    let dir = tempfile::tempdir().unwrap();
    let (hbbs, key) = spawn_hbbs(dir.path(), PORT_OUTAGE, Some(&url));
    wait_policy(PORT_OUTAGE, "mode=approved").await;
    sleep(Duration::from_millis(2500)).await;
    assert!(console.lock().unwrap().not_modified > 0, "an unchanged policy answers 304");
    assert!(dir.path().join("policy_snapshot.json").exists());

    console.lock().unwrap().fail = true;
    sleep(Duration::from_millis(2500)).await;
    let target = Peer::register(PORT_OUTAGE, "out-target").await;
    let mut conn = punch(PORT_OUTAGE, &key, &target.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;

    // Restart with the console still down: the cached snapshot applies.
    drop(hbbs);
    sleep(Duration::from_millis(500)).await;
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_OUTAGE, Some(&url));
    wait_policy(PORT_OUTAGE, "mode=approved").await;
    let target = Peer::register(PORT_OUTAGE, "out-target").await;
    let mut conn = punch(PORT_OUTAGE, &key, &target.id, "").await;
    assert_refused(&mut conn, DENY_UNAPPROVED, punch_hole_response::Failure::LICENSE_MISMATCH).await;
}

/// The LAN address a peer gives when asked for its local address reaches the
/// console, once.
#[tokio::test]
async fn lan_address_is_reported_to_the_console() {
    let (url, console) = start_console(serde_json::json!({
        "mode": "open", "allow": [], "incoming_only": [], "tokens": {}
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_LAN, Some(&url));
    wait_policy(PORT_LAN, "mode=open").await;
    let target = Peer::register(PORT_LAN, "lan-target").await;

    for _ in 0..2 {
        let mut conn = punch(PORT_LAN, &key, &target.id, "").await;
        let fla = assert_forwarded(&mut conn, &target).await;

        // The target answers the way the RustDesk client does.
        let mut answer = connect(PORT_LAN).await;
        let mut msg = RendezvousMessage::new();
        msg.set_local_addr(LocalAddr {
            socket_addr: fla.socket_addr,
            local_addr: AddrMangle::encode("192.168.77.20:50123".parse().unwrap()).into(),
            id: target.id.clone(),
            version: "1.4.3".to_owned(),
            ..Default::default()
        });
        send(&mut answer, msg).await;

        match reply(&mut conn, 3000).await.map(|m| m.union) {
            Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
                assert!(ph.is_local(), "the initiator gets the local address");
            }
            other => panic!("expected the local address, got {other:?}"),
        }
        sleep(Duration::from_millis(1500)).await;
    }

    let all: Vec<serde_json::Value> = console
        .lock()
        .unwrap()
        .reports
        .iter()
        .flat_map(|r| r["addrs"].as_array().cloned().unwrap_or_default())
        .collect();
    assert_eq!(all.len(), 1, "an unchanged address is reported once: {all:?}");
    assert_eq!(all[0]["id"], "lan-target");
    assert_eq!(all[0]["ip"], "192.168.77.20");
    assert!(all[0]["seen_at"].as_u64().unwrap() > 0);
}

/// A LAN address sent over WebSocket is attributed to the TCP peer, not to the
/// X-Real-IP header, which any client reaching the port can set. The answer
/// comes from 127.0.0.1, where the target registered, while the header claims
/// another address: the report must still arrive.
#[tokio::test]
async fn lan_address_over_websocket_ignores_forwarded_headers() {
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message},
    };

    let (url, console) = start_console(serde_json::json!({
        "mode": "open", "allow": [], "incoming_only": [], "tokens": {}
    }));
    let dir = tempfile::tempdir().unwrap();
    let (_hbbs, key) = spawn_hbbs(dir.path(), PORT_LAN_WS, Some(&url));
    wait_policy(PORT_LAN_WS, "mode=open").await;
    let target = Peer::register(PORT_LAN_WS, "lan-ws-target").await;

    let mut conn = punch(PORT_LAN_WS, &key, &target.id, "").await;
    let fla = assert_forwarded(&mut conn, &target).await;

    let mut req = format!("ws://127.0.0.1:{}", PORT_LAN_WS + 2)
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("X-Real-IP", HeaderValue::from_static("203.0.113.9"));
    let (mut ws, _) = connect_async(req).await.expect("websocket connects");
    let mut msg = RendezvousMessage::new();
    msg.set_local_addr(LocalAddr {
        socket_addr: fla.socket_addr,
        local_addr: AddrMangle::encode("192.168.77.30:50123".parse().unwrap()).into(),
        id: target.id.clone(),
        version: "1.4.3".to_owned(),
        ..Default::default()
    });
    ws.send(Message::Binary(msg.write_to_bytes().unwrap()))
        .await
        .expect("answer sent");

    match reply(&mut conn, 3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(ph))) => {
            assert!(ph.is_local(), "the initiator gets the local address");
        }
        other => panic!("expected the local address, got {other:?}"),
    }

    let mut all = vec![];
    for _ in 0..30 {
        all = console
            .lock()
            .unwrap()
            .reports
            .iter()
            .flat_map(|r| r["addrs"].as_array().cloned().unwrap_or_default())
            .collect();
        if !all.is_empty() {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(all.len(), 1, "the report arrives once: {all:?}");
    assert_eq!(all[0]["id"], "lan-ws-target");
    assert_eq!(all[0]["ip"], "192.168.77.30");
}
