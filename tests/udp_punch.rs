// Added by the CortenDesk Server project on 2026-11-04. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

//! UDP hole punching and IPv6 peer-to-peer for RustDesk 1.5 (issue #18),
//! against a real hbbs: the controller (A) over TCP from a non-loopback
//! address, the device (B) registered over UDP from 127.0.0.1, so the two are
//! not taken for the same LAN.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        net::{TcpStream, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use std::{
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket as StdUdp},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Hbbs {
    child: Child,
    _dir: tempfile::TempDir,
    port: u16,
    key: String,
}

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    loop {
        let main = TcpListener::bind("0.0.0.0:0").unwrap();
        let port = main.local_addr().unwrap().port();
        if !(1024..=65000).contains(&port) {
            continue;
        }
        if let (Ok(_), Ok(_), Ok(_)) = (
            TcpListener::bind(("0.0.0.0", port - 1)),
            TcpListener::bind(("0.0.0.0", port + 2)),
            StdUdp::bind(("0.0.0.0", port)),
        ) {
            return port;
        }
    }
}

async fn start(envs: &[(&str, &str)]) -> Hbbs {
    let dir = tempfile::tempdir().unwrap();
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir.path())
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .env_remove("ALWAYS_USE_RELAY")
        .env_remove("UDP_PUNCH")
        .env_remove("IPV6_PUNCH")
        .envs(envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut hbbs = Hbbs {
        child,
        _dir: dir,
        port,
        key: String::new(),
    };
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            if let Ok(key) = std::fs::read_to_string(hbbs._dir.path().join("id_ed25519.pub")) {
                hbbs.key = key.trim().to_owned();
                return hbbs;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("hbbs failed to start");
}

/// An address of this machine other than loopback.
fn non_loopback_ip() -> IpAddr {
    let socket = StdUdp::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    let ip = socket.local_addr().unwrap().ip();
    assert!(!ip.is_loopback() && !ip.is_unspecified(), "need a non-loopback address");
    ip
}

fn v6(s: &str) -> Bytes {
    AddrMangle::encode(s.parse::<SocketAddr>().unwrap()).into()
}

async fn udp_send(socket: &UdpSocket, port: u16, msg: &RendezvousMessage) {
    socket
        .send_to(&msg.write_to_bytes().unwrap(), ("127.0.0.1", port))
        .await
        .unwrap();
}

/// The next message on `socket` other than a registration reply.
async fn udp_recv(socket: &UdpSocket, ms: u64) -> Option<RendezvousMessage> {
    let mut buf = [0u8; 2048];
    loop {
        let (n, _) = timeout(Duration::from_millis(ms), socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
        if !msg.has_register_pk_response() && !msg.has_register_peer_response() {
            return Some(msg);
        }
    }
}

/// A device registered over UDP from 127.0.0.1.
async fn device(hbbs: &Hbbs, id: &str) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: id.as_bytes().to_vec().into(),
        pk: vec![7; 32].into(),
        ..Default::default()
    });
    udp_send(&socket, hbbs.port, &msg).await;
    let mut buf = [0u8; 256];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let reply = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
    assert_eq!(
        reply.register_pk_response().result.enum_value(),
        Ok(register_pk_response::Result::OK)
    );
    socket
}

type Tcp = Framed<TcpStream, BytesCodec>;

async fn controller(hbbs: &Hbbs) -> Tcp {
    let stream = TcpStream::connect((non_loopback_ip(), hbbs.port)).await.unwrap();
    Framed::new(stream, BytesCodec::new())
}

async fn tcp_send(tcp: &mut Tcp, msg: &RendezvousMessage) {
    tcp.send(Bytes::from(msg.write_to_bytes().unwrap())).await.unwrap();
}

/// The next message on `tcp`, skipping the server's key exchange offer.
async fn tcp_recv(tcp: &mut Tcp, ms: u64) -> Option<RendezvousMessage> {
    loop {
        let bytes = timeout(Duration::from_millis(ms), tcp.next()).await.ok()??.ok()?;
        let msg = RendezvousMessage::parse_from_bytes(&bytes).ok()?;
        if !msg.has_key_exchange() {
            return Some(msg);
        }
    }
}

fn request(hbbs: &Hbbs, id: &str, version: &str, udp_port: i32, socket_addr_v6: Bytes) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        licence_key: hbbs.key.clone(),
        version: version.to_owned(),
        udp_port,
        socket_addr_v6,
        ..Default::default()
    });
    msg
}

fn hole_sent(ph: &PunchHole, id: &str, version: &str, socket_addr_v6: Bytes) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: ph.socket_addr.clone(),
        id: id.to_owned(),
        version: version.to_owned(),
        socket_addr_v6,
        ..Default::default()
    });
    msg
}

/// UDP `TestNatRequest` gets the sender's port back, and only so often.
#[tokio::test]
async fn udp_nat_test_is_answered_and_rate_limited() {
    let hbbs = start(&[]).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_test_nat_request(TestNatRequest::default());
    udp_send(&socket, hbbs.port, &msg).await;
    let reply = udp_recv(&socket, 2000).await.expect("an answer");
    assert_eq!(reply.test_nat_response().port, socket.local_addr().unwrap().port() as i32);
    assert!(reply.test_nat_response().cu.is_none(), "never a ConfigUpdate");
    // A flood from one host: at most the burst is answered.
    for _ in 0..100 {
        udp_send(&socket, hbbs.port, &msg).await;
    }
    let mut answered = 0;
    while udp_recv(&socket, 300).await.is_some() {
        answered += 1;
    }
    assert!(answered < 60, "{answered} answers past the burst");
    assert!(answered > 40, "only {answered} answers");

    // Switched off: no answer at all.
    let off = start(&[("UDP_PUNCH", "N")]).await;
    udp_send(&socket, off.port, &msg).await;
    assert!(udp_recv(&socket, 500).await.is_none());
}

/// The whole UDP punch: the device gets the controller's UDP port and IPv6
/// address, answers over UDP from the socket it will punch with, and the
/// controller gets that socket's address over TCP, with `is_udp`.
#[tokio::test]
async fn udp_punch_and_ipv6_reach_both_sides() {
    let hbbs = start(&[]).await;
    let b = device(&hbbs, "123456801").await;
    let mut a = controller(&hbbs).await;
    tcp_send(&mut a, &request(&hbbs, "123456801", "1.5.0", 40000, v6("[2001:db8::5]:5000"))).await;
    let ph = udp_recv(&b, 2000).await.expect("punch hole").punch_hole().clone();
    assert_eq!(ph.udp_port, 40000);
    assert_eq!(AddrMangle::decode(&ph.socket_addr_v6), "[2001:db8::5]:5000".parse().unwrap());
    assert_eq!(ph.controlled_context.conn_audit_ref, "cd1/punch");

    let punch = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Forged: another device's ID. Ignored, and the route keeps waiting.
    udp_send(&punch, hbbs.port, &hole_sent(&ph, "999999999", "1.5.0", Bytes::new())).await;
    assert!(tcp_recv(&mut a, 500).await.is_none());
    // The real one, three copies as the client sends them.
    for _ in 0..3 {
        udp_send(&punch, hbbs.port, &hole_sent(&ph, "123456801", "1.5.0", v6("[2001:db8::6]:6000"))).await;
    }
    let resp = tcp_recv(&mut a, 2000).await.expect("response").punch_hole_response().clone();
    assert!(resp.is_udp);
    assert_eq!(AddrMangle::decode(&resp.socket_addr), punch.local_addr().unwrap());
    assert_eq!(AddrMangle::decode(&resp.socket_addr_v6), "[2001:db8::6]:6000".parse().unwrap());
    assert!(!resp.pk.is_empty(), "signed id and key");
    // No UDP packet to anyone, and one response only.
    assert!(udp_recv(&punch, 300).await.is_none());
    assert!(tcp_recv(&mut a, 500).await.is_none());
}

/// The device's IPv6 address comes back on the TCP path too, but only to a
/// controller whose own address went to it, and only a global one.
#[tokio::test]
async fn ipv6_comes_back_only_on_a_route() {
    let hbbs = start(&[]).await;
    let b = device(&hbbs, "123456802").await;
    let mut a = controller(&hbbs).await;
    tcp_send(&mut a, &request(&hbbs, "123456802", "1.5.0", 0, v6("[2001:db8::5]:5000"))).await;
    let ph = udp_recv(&b, 2000).await.unwrap().punch_hole().clone();
    assert_eq!(ph.udp_port, 0);
    assert!(!ph.socket_addr_v6.is_empty());
    let mut b_tcp = Framed::new(TcpStream::connect(("127.0.0.1", hbbs.port)).await.unwrap(), BytesCodec::new());
    tcp_send(&mut b_tcp, &hole_sent(&ph, "123456802", "1.5.0", v6("[2001:db8::6]:6000"))).await;
    let resp = tcp_recv(&mut a, 2000).await.unwrap().punch_hole_response().clone();
    assert!(!resp.is_udp);
    assert_eq!(AddrMangle::decode(&resp.socket_addr_v6), "[2001:db8::6]:6000".parse().unwrap());

    // A link-local address from the controller is not passed on.
    let mut a2 = controller(&hbbs).await;
    tcp_send(&mut a2, &request(&hbbs, "123456802", "1.5.0", 0, v6("[fe80::1]:5000"))).await;
    let ph = udp_recv(&b, 2000).await.unwrap().punch_hole().clone();
    assert!(ph.socket_addr_v6.is_empty());
    // And without a route the device's address does not go back either.
    let mut b_tcp = Framed::new(TcpStream::connect(("127.0.0.1", hbbs.port)).await.unwrap(), BytesCodec::new());
    tcp_send(&mut b_tcp, &hole_sent(&ph, "123456802", "1.5.0", v6("[2001:db8::6]:6000"))).await;
    let resp = tcp_recv(&mut a2, 2000).await.unwrap().punch_hole_response().clone();
    assert!(resp.socket_addr_v6.is_empty());
}

/// None of it for a controller before 1.5, one asking for a relay, a device
/// known to run an older client, or a server forcing the relay.
#[tokio::test]
async fn older_clients_and_forced_relay_get_a_plain_punch() {
    let hbbs = start(&[]).await;
    let b = device(&hbbs, "123456803").await;
    let plain = |ph: &PunchHole| ph.udp_port == 0 && ph.socket_addr_v6.is_empty();

    let mut a = controller(&hbbs).await;
    tcp_send(&mut a, &request(&hbbs, "123456803", "1.4.9", 40000, v6("[2001:db8::5]:5000"))).await;
    assert!(plain(udp_recv(&b, 2000).await.unwrap().punch_hole()), "1.4 controller");

    let mut a = controller(&hbbs).await;
    let mut msg = request(&hbbs, "123456803", "1.5.0", 40000, v6("[2001:db8::5]:5000"));
    if let Some(rendezvous_message::Union::PunchHoleRequest(r)) = msg.union.as_mut() {
        r.force_relay = true;
    }
    tcp_send(&mut a, &msg).await;
    assert!(plain(udp_recv(&b, 2000).await.unwrap().punch_hole()), "force_relay");

    // The device answers once as 1.4.9: from then on it gets a plain punch.
    let mut a = controller(&hbbs).await;
    tcp_send(&mut a, &request(&hbbs, "123456803", "1.5.0", 40000, Bytes::new())).await;
    let ph = udp_recv(&b, 2000).await.unwrap().punch_hole().clone();
    assert_eq!(ph.udp_port, 40000);
    let punch = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_send(&punch, hbbs.port, &hole_sent(&ph, "123456803", "1.4.9", Bytes::new())).await;
    assert!(tcp_recv(&mut a, 2000).await.unwrap().punch_hole_response().is_udp);
    let mut a = controller(&hbbs).await;
    tcp_send(&mut a, &request(&hbbs, "123456803", "1.5.0", 40000, v6("[2001:db8::5]:5000"))).await;
    assert!(plain(udp_recv(&b, 2000).await.unwrap().punch_hole()), "1.4 device");

    let relay = start(&[("ALWAYS_USE_RELAY", "Y")]).await;
    let b = device(&relay, "123456804").await;
    let mut a = controller(&relay).await;
    tcp_send(&mut a, &request(&relay, "123456804", "1.5.0", 40000, v6("[2001:db8::5]:5000"))).await;
    assert!(plain(udp_recv(&b, 2000).await.unwrap().punch_hole()), "ALWAYS_USE_RELAY");
}

/// A UDP `PunchHoleSent` with no route behind it is dropped: no reply to
/// anyone, as in 1.1.1.
#[tokio::test]
async fn unrequested_udp_hole_sent_is_ignored() {
    let hbbs = start(&[]).await;
    let mut a = controller(&hbbs).await;
    // A plain request, so the controller waits for a reply.
    let _b = device(&hbbs, "123456805").await;
    tcp_send(&mut a, &request(&hbbs, "123456805", "1.5.0", 0, Bytes::new())).await;
    sleep(Duration::from_millis(300)).await;
    let forger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ph = PunchHole {
        socket_addr: AddrMangle::encode(SocketAddr::new(non_loopback_ip(), 1)).into(),
        ..Default::default()
    };
    udp_send(&forger, hbbs.port, &hole_sent(&ph, "123456805", "1.5.0", Bytes::new())).await;
    assert!(udp_recv(&forger, 500).await.is_none());
    assert!(tcp_recv(&mut a, 500).await.is_none());
}
