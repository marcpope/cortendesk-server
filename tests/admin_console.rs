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
