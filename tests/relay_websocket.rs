//! hbbr relaying over WebSocket against a real hbbr process. The console's
//! in-browser client always reaches the relay over WebSocket (/ws/relay) and
//! the desktop peer usually over plain TCP, so both pairings must carry bytes
//! both ways, and the relay key must still be enforced on WebSocket.

use hbb_common::{
    bytes::Bytes,
    bytes_codec::BytesCodec,
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        net::TcpStream,
        time::{sleep, timeout},
    },
    tokio_util::codec::Framed,
};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// hbbr listens on PORT (TCP) and PORT + 2 (WebSocket). Clear of the other
// test files' ports.
const PORT: i32 = 31236;
const KEY: &str = "relay-test-key";

struct Hbbr(Child);

impl Drop for Hbbr {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn_hbbr(dir: &std::path::Path) -> Hbbr {
    let child = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir)
        .args(["-p", &PORT.to_string(), "-k", KEY])
        .env_remove("KEY")
        .env_remove("PORT")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("hbbr starts");
    for _ in 0..100 {
        if TcpStream::connect(format!("127.0.0.1:{}", PORT + 2)).await.is_ok() {
            return Hbbr(child);
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("hbbr never listened on {}", PORT + 2);
}

fn request_relay(uuid: &str, key: &str) -> Vec<u8> {
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        uuid: uuid.to_owned(),
        licence_key: key.to_owned(),
        ..Default::default()
    });
    msg.write_to_bytes().unwrap()
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn ws_join(uuid: &str, key: &str) -> Ws {
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{}", PORT + 2))
        .await
        .expect("websocket connects");
    ws.send(Message::Binary(request_relay(uuid, key).into()))
        .await
        .unwrap();
    ws
}

async fn ws_recv(ws: &mut Ws) -> Option<Vec<u8>> {
    loop {
        match timeout(Duration::from_secs(3), ws.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => return Some(b.to_vec()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

/// hbbr treats TCP from loopback as its admin channel, so a relay client has
/// to come in over another address of this machine.
fn non_loopback_ip() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

async fn tcp_join(ip: std::net::IpAddr, uuid: &str) -> Framed<TcpStream, BytesCodec> {
    let stream = TcpStream::connect((ip, PORT as u16)).await.unwrap();
    let mut framed = Framed::new(stream, BytesCodec::new());
    framed
        .send(Bytes::from(request_relay(uuid, KEY)))
        .await
        .unwrap();
    framed
}

#[tokio::test]
async fn relay_websocket_pairs_and_carries_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let _hbbr = spawn_hbbr(dir.path()).await;

    // WebSocket to WebSocket.
    let mut a = ws_join("ws-ws", KEY).await;
    sleep(Duration::from_millis(300)).await;
    let mut b = ws_join("ws-ws", KEY).await;
    sleep(Duration::from_millis(300)).await;
    a.send(Message::Binary(b"from a".to_vec().into())).await.unwrap();
    assert_eq!(ws_recv(&mut b).await.as_deref(), Some(&b"from a"[..]));
    b.send(Message::Binary(b"from b".to_vec().into())).await.unwrap();
    assert_eq!(ws_recv(&mut a).await.as_deref(), Some(&b"from b"[..]));

    // WebSocket (the browser) to TCP (a desktop peer).
    let ip = non_loopback_ip().expect("a non-loopback address to reach hbbr over TCP");
    let mut browser = ws_join("ws-tcp", KEY).await;
    sleep(Duration::from_millis(300)).await;
    let mut desktop = tcp_join(ip, "ws-tcp").await;
    sleep(Duration::from_millis(300)).await;
    browser
        .send(Message::Binary(b"to desktop".to_vec().into()))
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(3), desktop.next())
        .await
        .expect("desktop gets bytes")
        .expect("stream open")
        .expect("frame");
    assert_eq!(&got[..], b"to desktop");
    desktop.send(Bytes::from_static(b"to browser")).await.unwrap();
    assert_eq!(ws_recv(&mut browser).await.as_deref(), Some(&b"to browser"[..]));

    // A wrong key is refused on WebSocket too: the pair never forms.
    let mut x = ws_join("bad-key", "wrong").await;
    sleep(Duration::from_millis(300)).await;
    let mut y = ws_join("bad-key", "wrong").await;
    sleep(Duration::from_millis(300)).await;
    let _ = x.send(Message::Binary(b"leak".to_vec().into())).await;
    assert_eq!(ws_recv(&mut y).await, None, "no relay without the key");
}
