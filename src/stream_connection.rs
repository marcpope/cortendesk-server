// Added by the CortenDesk Server project on 2026-11-03, based on PR #1 by
// vk2amv. See CHANGES.md. This file is part of a modified version of
// rustdesk-server, distributed under the AGPL-3.0 like the original.

//! Ownership and bounded outbound queues for registered signalling streams.
use hbb_common::{
    anyhow::anyhow,
    tokio::sync::{mpsc, watch},
    ResultType,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) const HEARTBEAT_SECONDS: i32 = 20;
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const WRITE_TIMEOUT: u64 = 5_000;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Replies a connection may be owed at once: one per punch hole or relay
/// request it sent, as many attempts as a client makes.
const MAX_PENDING_REPLIES: u8 = 8;

#[derive(Clone)]
pub(crate) struct Connection {
    pub id: u64,
    pub addr: SocketAddr,
    pub ws: bool,
    tx: mpsc::Sender<Vec<u8>>,
    stop: Arc<watch::Sender<bool>>,
    closed: Arc<AtomicBool>,
    secure: Arc<AtomicBool>,
    replies: Arc<AtomicU8>,
}
impl Connection {
    pub fn new(
        addr: SocketAddr,
        ws: bool,
    ) -> (Self, mpsc::Receiver<Vec<u8>>, watch::Receiver<bool>) {
        let (tx, rx) = mpsc::channel(64);
        let (stop, cancelled) = watch::channel(false);
        (
            Self {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                addr,
                ws,
                tx,
                stop: Arc::new(stop),
                closed: Arc::new(AtomicBool::new(false)),
                secure: Arc::new(AtomicBool::new(false)),
                replies: Arc::new(AtomicU8::new(0)),
            },
            rx,
            cancelled,
        )
    }
    pub fn send(&self, bytes: Vec<u8>) -> ResultType<()> {
        if self.is_closed() {
            return Err(anyhow!("signalling connection is closed"));
        }
        if let Err(err) = self.tx.try_send(bytes) {
            self.close();
            return Err(anyhow!("signalling queue unavailable: {}", err));
        }
        Ok(())
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.stop.send(true);
    }
    /// The connection sent a request that gets one reply addressed to it.
    pub fn expect_reply(&self) {
        let _ = self
            .replies
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_PENDING_REPLIES).then_some(n + 1)
            });
    }
    /// Use up one owed reply. False when none is owed: the connection did not
    /// ask, so nothing addressed to it by IP and port is delivered.
    pub fn take_reply(&self) -> bool {
        self.replies
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
    }
    pub fn set_secure(&self) {
        self.secure.store(true, Ordering::Release);
    }
    pub fn is_secure(&self) -> bool {
        self.secure.load(Ordering::Acquire)
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

pub(crate) struct Registration {
    pub connection: Connection,
    pub last_seen: Instant,
}
impl Registration {
    pub fn alive(&self) -> bool {
        !self.connection.is_closed() && self.last_seen.elapsed() < RECEIVE_TIMEOUT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    #[test]
    fn replies_are_owed_per_request_and_capped() {
        let (c, _rx, _stop) = Connection::new("127.0.0.1:1".parse().unwrap(), false);
        assert!(!c.take_reply());
        c.expect_reply();
        assert!(c.take_reply());
        assert!(!c.take_reply());
        for _ in 0..20 {
            c.expect_reply();
        }
        let owed = (0..20).filter(|_| c.take_reply()).count();
        assert_eq!(owed, MAX_PENDING_REPLIES as usize);
    }

    #[hbb_common::tokio::test]
    async fn slow_writer_is_cancelled_and_queued_messages_are_ordered() {
        let (connection, mut rx, cancelled) = Connection::new("127.0.0.1:1".parse().unwrap(), true);
        for n in 0..64 {
            connection.send(vec![n]).unwrap();
        }
        assert!(connection.send(vec![64]).is_err());
        assert!(*cancelled.borrow());
        assert!(connection.is_closed());
        assert!(connection.send(vec![65]).is_err());
        for n in 0..64 {
            assert_eq!(rx.recv().await.unwrap(), vec![n]);
        }
    }
}
