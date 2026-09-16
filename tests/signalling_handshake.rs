//! End-to-end test of the encrypted signalling handshake against a real hbbs
//! process: spawn the server, speak the client half of the exchange over a real
//! socket, and check that ordinary signalling still works afterwards — both for
//! a client that encrypts and one that does not.
//!
//! The client half is written to the algorithm the RustDesk client uses. That
//! is the point of the test: it fails if our end drifts away from theirs.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tcp::Encrypt,
    tokio::{self, net::TcpStream, time::sleep},
    tokio_util::codec::Framed,
};
use sodiumoxide::crypto::{box_, secretbox, sign};
use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};

// One port set per test: the tests run concurrently and each starts its own
// server, so sharing a port would leave a client verifying one server's offer
// against another server's key. hbbs also claims port-1 and port+2.
const PORT_SECURED: i32 = 31116;
const PORT_PLAIN: i32 = 31126;
const PORT_WS: i32 = 31136;

/// A running hbbs that is killed when the test ends, however it ends.
struct Hbbs(Child);

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start hbbs in a scratch directory and wait until it announces its key.
/// Returns the server's public key, which is what a client is configured with.
///
/// Set `TEST_HBBS_ADDR` (`host:port`) and `TEST_HBBS_KEY` (its public key) to
/// run these checks against a server that is already running instead — a
/// container, or a real deployment you want to verify.
fn start_hbbs(dir: &std::path::Path, port: i32) -> (Option<Hbbs>, sign::PublicKey, String) {
    if let (Ok(_), Ok(key)) = (
        std::env::var("TEST_HBBS_ADDR"),
        std::env::var("TEST_HBBS_KEY"),
    ) {
        let raw = base64::decode(&key).expect("TEST_HBBS_KEY is base64");
        let pk = sign::PublicKey::from_slice(&raw).expect("TEST_HBBS_KEY is a public key");
        return (None, pk, key);
    }
    let (child, pk, key) = spawn_hbbs(dir, port);
    (Some(child), pk, key)
}

fn spawn_hbbs(dir: &std::path::Path, port: i32) -> (Hbbs, sign::PublicKey, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir)
        .args(["-p", &port.to_string(), "-k", "_"])
        // The startup self-test would keep a UDP conversation going with itself
        // for the life of the process; it proves nothing here.
        .env("TEST_HBBS", "no")
        .env("RUST_LOG", "info")
        .env("TOKIO_WORKER_THREADS", "2")
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

async fn connect(port: i32) -> Framed<TcpStream, BytesCodec> {
    let addr = std::env::var("TEST_HBBS_ADDR").unwrap_or(format!("127.0.0.1:{port}"));
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(&addr).await {
            return Framed::new(s, BytesCodec::new());
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbs never accepted a connection on {addr}");
}

/// Client half of the exchange: verify the server's signed throwaway key, mint
/// a symmetric key for this connection, seal it back.
fn client_reply(offer: &[u8], server_pk: &sign::PublicKey) -> (RendezvousMessage, secretbox::Key) {
    let msg_in = RendezvousMessage::parse_from_bytes(offer).expect("offer parses");
    let ex = match msg_in.union {
        Some(rendezvous_message::Union::KeyExchange(ex)) => ex,
        other => panic!("expected a key exchange, got {other:?}"),
    };
    assert_eq!(ex.keys.len(), 1, "the offer carries exactly one signed key");

    let their_pk_b = sign::verify(&ex.keys[0], server_pk).expect("offer is signed by the server");
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
    (msg_out, key)
}

/// What a client puts on the wire once it wants to reach a peer. `licence_key`
/// is the server key the client is configured with; hbbs rejects the request
/// outright if it does not match, so getting past that check also proves the
/// encrypted frame arrived intact.
fn punch_hole_request(token: &str, licence_key: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: "000000000".to_owned(),
        token: token.to_owned(),
        licence_key: licence_key.to_owned(),
        version: "1.4.3".to_owned(),
        ..Default::default()
    });
    msg
}

fn assert_id_not_exist(bytes: &[u8]) {
    let msg = RendezvousMessage::parse_from_bytes(bytes).expect("response parses");
    match msg.union {
        Some(rendezvous_message::Union::PunchHoleResponse(ph)) => assert_eq!(
            ph.failure.enum_value(),
            Ok(punch_hole_response::Failure::ID_NOT_EXIST),
            "unknown id should come back as ID_NOT_EXIST"
        ),
        other => panic!("expected a punch hole response, got {other:?}"),
    }
}

/// A signed-in client: encrypt the channel, then punch. This is the case that
/// fails against an unpatched server — the client waits for an offer that never
/// arrives and gives up with "Failed to secure tcp".
#[tokio::test]
async fn signed_in_client_secures_the_channel_and_gets_a_reply() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (_hbbs, server_pk, server_key) = start_hbbs(dir.path(), PORT_SECURED);
    let (mut sink, mut stream) = connect(PORT_SECURED).await.split();

    let offer = stream.next().await.expect("offer sent").expect("offer read");
    let (reply, key) = client_reply(&offer, &server_pk);
    sink.send(Bytes::from(reply.write_to_bytes().unwrap()))
        .await
        .expect("reply sent");
    let mut cipher = Encrypt::new(key);

    // Everything from here is encrypted, in both directions.
    let request = punch_hole_request("a-console-access-token", &server_key);
    sink.send(Bytes::from(cipher.enc(&request.write_to_bytes().unwrap())))
        .await
        .expect("request sent");

    let mut bytes = stream
        .next()
        .await
        .expect("response sent")
        .expect("response read");
    cipher.dec(&mut bytes).expect("response decrypts");
    assert_id_not_exist(&bytes);
}

/// A signed-out client never answers the offer. It must still be served, in
/// plain text, exactly as before — the offer is skipped, not answered.
#[tokio::test]
async fn plain_client_is_unaffected_by_the_offer() {
    let dir = tempfile::tempdir().expect("scratch dir");
    let (_hbbs, _server_pk, server_key) = start_hbbs(dir.path(), PORT_PLAIN);
    let (mut sink, mut stream) = connect(PORT_PLAIN).await.split();

    let request = punch_hole_request("", &server_key);
    sink.send(Bytes::from(request.write_to_bytes().unwrap()))
        .await
        .expect("request sent");

    // The client skips key exchange frames it did not ask for (RustDesk has
    // done this since 1.2.0), so do the same and read on to the real reply.
    let mut response = None;
    for _ in 0..3 {
        let bytes = stream.next().await.expect("a frame").expect("frame read");
        let msg = RendezvousMessage::parse_from_bytes(&bytes).expect("frame parses");
        if matches!(msg.union, Some(rendezvous_message::Union::KeyExchange(_))) {
            continue;
        }
        response = Some(bytes);
        break;
    }
    assert_id_not_exist(&response.expect("a non key exchange reply"));
}

/// The WebSocket path must stay silent. Clients skip this exchange there —
/// the transport already handles encryption — so an offer on that port would
/// arrive unasked for and confuse an in-browser client.
#[tokio::test]
async fn websocket_clients_are_not_offered_an_exchange() {
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let dir = tempfile::tempdir().expect("scratch dir");
    let (_hbbs, _server_pk, server_key) = start_hbbs(dir.path(), PORT_WS);
    // hbbs serves the rendezvous protocol over WebSocket on its port + 2.
    let (host, port) = match std::env::var("TEST_HBBS_ADDR") {
        Ok(addr) => {
            let (h, p) = addr.rsplit_once(':').expect("TEST_HBBS_ADDR is host:port");
            (h.to_owned(), p.parse::<i32>().expect("port is a number"))
        }
        Err(_) => ("127.0.0.1".to_owned(), PORT_WS),
    };
    let url = format!("ws://{host}:{}", port + 2);

    let mut ws = None;
    for _ in 0..100 {
        if let Ok((s, _)) = connect_async(&url).await {
            ws = Some(s);
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let (mut sink, mut stream) = ws.expect("websocket connects").split();

    if let Ok(Some(frame)) = hbb_common::timeout(500, stream.next()).await {
        panic!("nothing should be sent unprompted over websocket, got {frame:?}");
    }

    // And normal signalling still works on that transport.
    let request = punch_hole_request("", &server_key);
    sink.send(Message::Binary(request.write_to_bytes().unwrap()))
        .await
        .expect("request sent");
    match stream.next().await.expect("a reply").expect("reply read") {
        Message::Binary(bytes) => assert_id_not_exist(&bytes),
        other => panic!("expected a binary frame, got {other:?}"),
    }
}
