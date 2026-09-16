//! Ownership and bounded outbound queues for registered signalling streams.
use hbb_common::{
    anyhow::anyhow,
    tokio::sync::{mpsc, watch},
    ResultType,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) const HEARTBEAT_SECONDS: i32 = 20;
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const WRITE_TIMEOUT: u64 = 5_000;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) struct Connection {
    pub id: u64,
    pub addr: SocketAddr,
    pub ws: bool,
    tx: mpsc::Sender<Vec<u8>>,
    stop: Arc<watch::Sender<bool>>,
    closed: Arc<AtomicBool>,
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
