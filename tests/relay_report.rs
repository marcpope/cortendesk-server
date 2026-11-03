//! hbbr reporting relayed sessions to a CortenDesk console (issue #130),
//! against a real hbbr process and a stand-in console that records what it
//! is sent. The controller's request names the device and the connection
//! type; the device's does not, and either may arrive first.

use hbb_common::{
    futures_util::{sink::SinkExt, stream::StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::mpsc,
        time::{sleep, timeout},
    },
};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

// hbbr listens on PORT (TCP) and PORT + 2 (WebSocket). Clear of the other
// test files' ports.
const PORT: i32 = 31266;
const SECRET: &str = "test-link-secret";

struct Hbbr(Child);

impl Drop for Hbbr {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A console that answers 200 to everything and hands over each request's
/// authorization header and body.
async fn fake_console() -> (String, mpsc::UnboundedReceiver<(String, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let Some(end) = text.find("\r\n\r\n") else { continue };
                    let head = &text[..end];
                    let len = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if buf.len() < end + 4 + len {
                        continue;
                    }
                    let auth = head
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().starts_with("authorization:").then(|| l[14..].trim().to_owned()))
                        .unwrap_or_default();
                    let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
                    let body = String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).to_string();
                    tx.send((format!("{path} {auth}"), body)).ok();
                    s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
                        .await
                        .ok();
                    return;
                }
            });
        }
    });
    (url, rx)
}

async fn spawn_hbbr(dir: &std::path::Path, console: &str) -> Hbbr {
    let child = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir)
        .args(["-p", &PORT.to_string()])
        .env_remove("KEY")
        .env_remove("PORT")
        .env("CORTENDESK_CONSOLE_URL", console)
        .env("CORTENDESK_SERVER_SECRET", SECRET)
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

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;

async fn join(uuid: &str, id: &str, conn_type: ConnType) -> Ws {
    let (mut ws, _) = connect_async(format!("ws://127.0.0.1:{}", PORT + 2))
        .await
        .expect("websocket connects");
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        uuid: uuid.to_owned(),
        id: id.to_owned(),
        conn_type: conn_type.into(),
        ..Default::default()
    });
    ws.send(Message::Binary(msg.write_to_bytes().unwrap().into()))
        .await
        .unwrap();
    ws
}

async fn next_report(rx: &mut mpsc::UnboundedReceiver<(String, String)>) -> (String, serde_json::Value) {
    let (head, body) = timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("a report within 15s")
        .expect("console still listening");
    (head, serde_json::from_str(&body).expect("json body"))
}

#[tokio::test]
async fn a_relayed_session_is_reported_when_it_opens_and_closes() {
    let (console, mut rx) = fake_console().await;
    let dir = tempfile::tempdir().unwrap();
    let _hbbr = spawn_hbbr(dir.path(), &console).await;

    // The device gets there first, as it usually does on a forced relay.
    let mut device = join("uuid-1", "", ConnType::DEFAULT_CONN).await;
    sleep(Duration::from_millis(300)).await;
    let mut controller = join("uuid-1", "123456789", ConnType::FILE_TRANSFER).await;
    sleep(Duration::from_millis(300)).await;
    controller
        .send(Message::Binary(vec![1u8; 1000].into()))
        .await
        .unwrap();
    let got = timeout(Duration::from_secs(3), device.next()).await.expect("relayed");
    assert!(matches!(got, Some(Ok(Message::Binary(_)))));

    let (head, open) = next_report(&mut rx).await;
    assert_eq!(head, format!("/api/server/relay-sessions Bearer {SECRET}"));
    let s = &open["sessions"][0];
    assert_eq!(s["uuid"], "uuid-1");
    assert_eq!(s["id"], "123456789");
    assert_eq!(s["conn_type"], 1);
    assert_eq!(s["controller_ip"], "127.0.0.1");
    assert!(s["started_at"].as_u64().unwrap() > 0);
    assert!(s.get("ended_at").is_none(), "still open");

    drop(controller);
    drop(device);
    let (_, closed) = next_report(&mut rx).await;
    let s = &closed["sessions"][0];
    assert_eq!(s["uuid"], "uuid-1");
    assert!(s["ended_at"].as_u64().unwrap() >= s["started_at"].as_u64().unwrap());
    assert!(s["bytes"].as_u64().unwrap() >= 1000, "counts what it carried: {s}");
}
