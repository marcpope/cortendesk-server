//! End-to-end test of WebRTC signalling (RustDesk 1.5) against a real hbbs
//! process: a controller's offer reaches the device, the device's answer and
//! ICE candidates reach the controller, the controller's candidates reach the
//! device, and nothing travels for a connection that is not encrypted or to a
//! device it did not offer to.
//!
//! The device registers from 127.0.0.2 and the controller connects from
//! 127.0.0.1, so hbbs sees two hosts and sends `PunchHole` rather than asking
//! for LAN addresses. That needs Linux, where all of 127/8 is on loopback.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::Encrypt,
    tokio::{
        self,
        net::{TcpSocket, UdpSocket},
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
    AddrMangle,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};

// One port per test, clear of the other test files. hbbs also claims port-1
// and port+2.
const PORT_EXCHANGE: i32 = 31246;
const PORT_PLAIN: i32 = 31256;

const CONTROLLER_IP: &str = "127.0.0.1";
const DEVICE_IP: &str = "127.0.0.2";

struct Hbbs(Child);

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_hbbs(dir: &std::path::Path, port: i32) -> (Hbbs, sign::PublicKey, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        .env("TEST_HBBS", "no")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hbbs starts");
    let stdout = child.stdout.take().expect("stdout piped");
    let mut key = None;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(k) = line.split("Key: ").nth(1) {
            key = Some(k.trim().to_owned());
            break;
        }
    }
    let key = key.expect("hbbs logs its key");
    let raw = base64::decode(&key).expect("key is base64");
    let pk = sign::PublicKey::from_slice(&raw).expect("key is an ed25519 public key");
    (Hbbs(child), pk, key)
}

/// A device's UDP registration: where hbbs forwards requests for it.
struct Device {
    sock: UdpSocket,
    id: String,
}

impl Device {
    async fn register(port: i32, id: &str) -> Device {
        let sock = UdpSocket::bind(format!("{DEVICE_IP}:0")).await.unwrap();
        let mut msg = RendezvousMessage::new();
        msg.set_register_pk(RegisterPk {
            id: id.to_owned(),
            uuid: format!("uuid-{id}").into_bytes().into(),
            pk: vec![7u8; 32].into(),
            ..Default::default()
        });
        let bytes = msg.write_to_bytes().unwrap();
        let mut buf = [0u8; 4096];
        for _ in 0..50 {
            sock.send_to(&bytes, format!("127.0.0.1:{port}")).await.ok();
            if let Ok(Ok((n, _))) = timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await {
                let res = RendezvousMessage::parse_from_bytes(&buf[..n]).unwrap();
                if matches!(res.union, Some(rendezvous_message::Union::RegisterPkResponse(_))) {
                    return Device { sock, id: id.to_owned() };
                }
            }
        }
        panic!("hbbs never answered RegisterPk for {id}");
    }

    /// What hbbs forwarded to this device within `ms`, if anything.
    async fn forwarded(&self, ms: u64) -> Option<RendezvousMessage> {
        let mut buf = [0u8; 65536];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (n, _) = timeout(left, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
            let msg = RendezvousMessage::parse_from_bytes(&buf[..n]).ok()?;
            if !matches!(msg.union, Some(rendezvous_message::Union::RegisterPkResponse(_))) {
                return Some(msg);
            }
        }
    }
}

/// A TCP connection to hbbs, encrypted the way the client does it or not at all.
struct Conn {
    framed: Framed<tokio::net::TcpStream, BytesCodec>,
    cipher: Option<Encrypt>,
}

impl Conn {
    async fn open(port: i32, from: &str, server_pk: Option<&sign::PublicKey>) -> Conn {
        let mut framed = None;
        for _ in 0..100 {
            let s = TcpSocket::new_v4().unwrap();
            s.bind(format!("{from}:0").parse().unwrap()).unwrap();
            if let Ok(s) = s.connect(format!("127.0.0.1:{port}").parse().unwrap()).await {
                framed = Some(Framed::new(s, BytesCodec::new()));
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        let mut framed = framed.expect("hbbs accepts connections");
        // hbbs opens every plain TCP connection with its key exchange offer.
        let offer = framed.next().await.expect("offer sent").expect("offer read");
        let cipher = server_pk.map(|pk| {
            let (reply, key) = client_reply(&offer, pk);
            (reply, Encrypt::new(key))
        });
        let cipher = match cipher {
            Some((reply, cipher)) => {
                framed
                    .send(Bytes::from(reply.write_to_bytes().unwrap()))
                    .await
                    .expect("reply sent");
                Some(cipher)
            }
            None => None,
        };
        Conn { framed, cipher }
    }

    fn local_addr(&self) -> SocketAddr {
        self.framed.get_ref().local_addr().unwrap()
    }

    async fn send(&mut self, msg: RendezvousMessage) {
        let mut bytes = msg.write_to_bytes().unwrap();
        if let Some(c) = self.cipher.as_mut() {
            bytes = c.enc(&bytes);
        }
        self.framed.send(Bytes::from(bytes)).await.expect("sent");
    }

    async fn recv(&mut self, ms: u64) -> Option<RendezvousMessage> {
        let mut bytes = match timeout(Duration::from_millis(ms), self.framed.next()).await {
            Ok(Some(Ok(b))) => b,
            _ => return None,
        };
        if let Some(c) = self.cipher.as_mut() {
            c.dec(&mut bytes).expect("decrypts");
        }
        Some(RendezvousMessage::parse_from_bytes(&bytes).expect("parses"))
    }
}

fn client_reply(offer: &[u8], server_pk: &sign::PublicKey) -> (RendezvousMessage, secretbox::Key) {
    let msg_in = RendezvousMessage::parse_from_bytes(offer).expect("offer parses");
    let ex = match msg_in.union {
        Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
        other => panic!("expected a key exchange, got {other:?}"),
    };
    let their_pk_b = sign::verify(&ex.keys[0], server_pk).expect("offer is signed by the server");
    let mut pk_ = [0u8; box_::PUBLICKEYBYTES];
    pk_.copy_from_slice(&their_pk_b);
    let (our_pk_b, our_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(pk_), &our_sk_b);
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_key_exchange(KeyExchange {
        keys: vec![Vec::from(our_pk_b.0).into(), sealed.into()],
        ..Default::default()
    });
    (msg_out, key)
}

fn offer_to(target: &str, key: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: target.to_owned(),
        licence_key: key.to_owned(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_offer: "webrtc://b2ZmZXI=".to_owned(),
        ..Default::default()
    });
    msg
}

fn candidate(id: &str, socket_addr: &[u8], text: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_ice_candidate(IceCandidate {
        id: id.to_owned(),
        socket_addr: socket_addr.to_vec().into(),
        session_key: "sha-256 AA:BB".to_owned(),
        candidate: text.to_owned(),
        ..Default::default()
    });
    msg
}

fn expect_candidate(msg: Option<RendezvousMessage>, text: &str) {
    match msg.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::IceCandidate(ice))) => {
            assert_eq!(ice.candidate, text);
            assert_eq!(ice.session_key, "sha-256 AA:BB");
            assert!(ice.id.is_empty() && ice.socket_addr.is_empty(), "routing fields are not passed on");
        }
        other => panic!("expected candidate {text}, got {other:?}"),
    }
}

/// The whole exchange, punch path: offer out, candidates both ways before and
/// after the answer, answer back, and the controller's connection still
/// usable after the reply that would normally consume it.
#[tokio::test]
async fn offer_answer_and_candidates_travel_between_the_two() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (_hbbs, pk, key) = spawn_hbbs(dir.path(), PORT_EXCHANGE);
    let device = Device::register(PORT_EXCHANGE, "111111111").await;
    let bystander = Device::register(PORT_EXCHANGE, "222222222").await;

    let mut controller = Conn::open(PORT_EXCHANGE, CONTROLLER_IP, Some(&pk)).await;
    controller.send(offer_to(&device.id, &key)).await;

    let ph = match device.forwarded(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHole(ph))) => ph,
        other => panic!("expected a punch hole with the offer, got {other:?}"),
    };
    assert_eq!(ph.webrtc_sdp_offer, "webrtc://b2ZmZXI=");
    assert_eq!(AddrMangle::decode(&ph.socket_addr), controller.local_addr());
    // The device echoes this in its connection audit (issue #130).
    assert_eq!(ph.controlled_context.conn_audit_ref, "cd1/punch-webrtc");

    // The device trickles over a connection of its own, which stays open.
    let mut trickle = Conn::open(PORT_EXCHANGE, DEVICE_IP, Some(&pk)).await;
    trickle.send(candidate("", &ph.socket_addr, "device-1")).await;
    expect_candidate(controller.recv(3000).await, "device-1");

    let mut answer = Conn::open(PORT_EXCHANGE, DEVICE_IP, Some(&pk)).await;
    let mut sent = RendezvousMessage::new();
    sent.set_punch_hole_sent(PunchHoleSent {
        socket_addr: ph.socket_addr.clone(),
        id: device.id.clone(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_answer: "webrtc://YW5zd2Vy".to_owned(),
        ..Default::default()
    });
    answer.send(sent).await;
    match controller.recv(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHoleResponse(r))) => {
            assert_eq!(r.webrtc_sdp_answer, "webrtc://YW5zd2Vy");
        }
        other => panic!("expected the answer, got {other:?}"),
    }

    trickle.send(candidate("", &ph.socket_addr, "device-2")).await;
    expect_candidate(controller.recv(3000).await, "device-2");

    controller.send(candidate(&device.id, &[], "controller-1")).await;
    expect_candidate(device.forwarded(3000).await, "controller-1");

    // A route goes to the device offered to and no other.
    controller.send(candidate(&bystander.id, &[], "stray")).await;
    assert!(bystander.forwarded(1000).await.is_none(), "nothing reaches another device");
}

/// An offer on a connection that is not encrypted goes no further, and opens
/// nothing for candidates in either direction.
#[tokio::test]
async fn an_unencrypted_offer_is_dropped() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (_hbbs, pk, key) = spawn_hbbs(dir.path(), PORT_PLAIN);
    let device = Device::register(PORT_PLAIN, "333333333").await;

    let mut controller = Conn::open(PORT_PLAIN, CONTROLLER_IP, None).await;
    controller.send(offer_to(&device.id, &key)).await;

    let ph = match device.forwarded(3000).await.map(|m| m.union) {
        Some(Some(rendezvous_message::Union::PunchHole(ph))) => ph,
        other => panic!("expected a punch hole, got {other:?}"),
    };
    assert!(ph.webrtc_sdp_offer.is_empty(), "the offer is not passed on");
    assert_eq!(ph.controlled_context.conn_audit_ref, "cd1/punch");

    controller.send(candidate(&device.id, &[], "controller-1")).await;
    assert!(device.forwarded(1000).await.is_none(), "no candidates to the device");

    let mut trickle = Conn::open(PORT_PLAIN, DEVICE_IP, Some(&pk)).await;
    trickle.send(candidate("", &ph.socket_addr, "device-1")).await;
    assert!(controller.recv(1000).await.is_none(), "no candidates to the controller");
}
