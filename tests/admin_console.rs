// Added by the CortenDesk Server project on 2026-11-04. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

//! The loopback admin consoles of hbbs and hbbr, against real processes.

use hbb_common::tokio::{
    self,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

// hbbs uses PORT_HBBS - 1 (the admin console), PORT_HBBS and PORT_HBBS + 2.
// Clear of the other test files' ports.
const PORT_HBBS: u16 = 31286;
// hbbr uses PORT_HBBR (relay and, from loopback, the admin console) and
// PORT_HBBR + 2.
const PORT_HBBR: u16 = 31306;

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for(port: u16, child: Child) -> Process {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Process(child);
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("nothing listened on {port}");
}

async fn command(port: u16, cmd: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(cmd.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    reply
}

/// `always-use-relay Y` turns the flag on and leaves the relay list alone
/// (issue #4). Before, the argument replaced the relay list.
#[tokio::test]
async fn always_use_relay_keeps_the_relay_servers() {
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbs"))
        .current_dir(dir.path())
        .args(["-p", &PORT_HBBS.to_string(), "-r", "127.0.0.1:21117"])
        .env_remove("RELAY_SERVERS")
        .env_remove("ALWAYS_USE_RELAY")
        .env("TEST_HBBS", "no")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let console = PORT_HBBS - 1;
    let _hbbs = wait_for(console, child).await;
    assert_eq!(command(console, "rs").await, "127.0.0.1:21117\n");
    command(console, "aur Y").await;
    sleep(Duration::from_millis(200)).await;
    assert_eq!(command(console, "aur").await, "ALWAYS_USE_RELAY: true\n");
    assert_eq!(command(console, "rs").await, "127.0.0.1:21117\n");
    command(console, "aur N").await;
    sleep(Duration::from_millis(200)).await;
    assert_eq!(command(console, "aur").await, "ALWAYS_USE_RELAY: false\n");
    assert_eq!(command(console, "rs").await, "127.0.0.1:21117\n");
}

/// A reply bigger than the socket buffers arrives whole even when the reader
/// is slow (issue #8). Before, the console wrote it once and closed, so a
/// long one, such as a big block list, came back cut short.
#[tokio::test]
async fn long_console_reply_arrives_whole() {
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_hbbr"))
        .current_dir(dir.path())
        .args(["-p", &PORT_HBBR.to_string()])
        .env_remove("KEY")
        .env_remove("PORT")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _hbbr = wait_for(PORT_HBBR, child).await;
    // 3000 entries of 1000 bytes; the console reads one 1 KB command at a time.
    let entries = 3000;
    for i in 0..entries {
        command(PORT_HBBR, &format!("Ba {:0>1000}", i)).await;
    }
    let mut stream = TcpStream::connect(("127.0.0.1", PORT_HBBR)).await.unwrap();
    stream.write_all(b"B").await.unwrap();
    sleep(Duration::from_secs(1)).await;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();
    assert_eq!(reply.lines().count(), entries);
    assert_eq!(reply.len(), entries * 1001);
}
