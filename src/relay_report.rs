// Added by the CortenDesk Server project on 2026-11-03. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

//! Relay sessions reported to a CortenDesk console (issue #130).
//!
//! A device's connection audit does not say how the session got through, and
//! a punch hole can still end up here. This relay is the only place that
//! knows a session ran through it, so it tells the console when a pair opens
//! and when it closes, with the bytes it carried. The console matches that to
//! the device's own record of the connection.
//!
//! Reports are queued and sent in batches every few seconds, so relaying never
//! waits on HTTP. Nothing here runs unless both `CORTENDESK_CONSOLE_URL` and
//! `CORTENDESK_SERVER_SECRET` are set.

use hbb_common::{log, tokio};
use serde_derive::Serialize;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const EVERY: Duration = Duration::from_secs(5);
/// Reports kept while the console is unreachable. The oldest go first.
const MAX_PENDING: usize = 5000;
/// Most reports in one request; the console accepts up to 500.
const BATCH: usize = 500;

static ON: AtomicBool = AtomicBool::new(false);

lazy_static::lazy_static! {
    static ref PENDING: Mutex<Vec<Session>> = Default::default();
}

/// One relayed session. Sent once when it opens and again, with `ended_at`
/// and `bytes`, when it closes. The console keys both on `uuid`.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub uuid: String,
    /// The device being connected to, from the controller's request.
    pub id: String,
    /// RustDesk's ConnType: 0 remote, 1 file transfer, 2 port forward,
    /// 3 RDP, 4 view camera, 5 terminal.
    pub conn_type: i32,
    pub controller_ip: String,
    pub device_ip: String,
    pub started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<u64>,
    pub bytes: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub fn start() {
    let url = crate::common::get_arg_opt("CORTENDESK_CONSOLE_URL")
        .unwrap_or_default()
        .trim()
        .trim_end_matches('/')
        .to_owned();
    let secret = crate::common::get_arg_opt("CORTENDESK_SERVER_SECRET")
        .unwrap_or_default()
        .trim()
        .to_owned();
    if url.is_empty() || secret.is_empty() {
        log::info!("Console link off: set CORTENDESK_CONSOLE_URL and CORTENDESK_SERVER_SECRET to report relay sessions");
        return;
    }
    ON.store(true, Ordering::SeqCst);
    log::info!("Console link: {url}, relay sessions reported every {}s", EVERY.as_secs());
    tokio::spawn(run(url, secret));
}

/// A pair just formed. Whichever side named a device is the controller: the
/// device's own request carries only the uuid. None when neither did (a
/// client too old to send it), as there is nothing to match it to.
pub fn opened(
    uuid: &str,
    this: (&str, i32, SocketAddr),
    waiting: (&str, i32, SocketAddr),
) -> Option<Session> {
    if !ON.load(Ordering::SeqCst) {
        return None;
    }
    let (controller, device) = if !this.0.is_empty() {
        (this, waiting)
    } else if !waiting.0.is_empty() {
        (waiting, this)
    } else {
        return None;
    };
    let session = Session {
        uuid: uuid.to_owned(),
        id: controller.0.to_owned(),
        conn_type: controller.1,
        // hbbr listens on IPv6, so IPv4 peers arrive as ::ffff:a.b.c.d.
        controller_ip: hbb_common::try_into_v4(controller.2).ip().to_string(),
        device_ip: hbb_common::try_into_v4(device.2).ip().to_string(),
        started_at: now_secs(),
        ended_at: None,
        bytes: 0,
    };
    queue(session.clone());
    Some(session)
}

pub fn closed(mut session: Session, bytes: usize) {
    session.ended_at = Some(now_secs());
    session.bytes = bytes as u64;
    queue(session);
}

fn queue(session: Session) {
    let Ok(mut pending) = PENDING.lock() else { return };
    if pending.len() >= MAX_PENDING {
        pending.remove(0);
    }
    pending.push(session);
}

async fn run(url: String, secret: String) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("cortendesk-server/{}", crate::version::VERSION))
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            log::error!("Console link: no HTTP client: {err}");
            return;
        }
    };
    let mut failing = false;
    loop {
        tokio::time::sleep(EVERY).await;
        loop {
            let batch: Vec<Session> = match PENDING.lock() {
                Ok(mut p) => {
                    let n = p.len().min(BATCH);
                    p.drain(..n).collect()
                }
                Err(_) => break,
            };
            if batch.is_empty() {
                break;
            }
            let ok = client
                .post(format!("{url}/api/server/relay-sessions"))
                .bearer_auth(&secret)
                .json(&serde_json::json!({ "sessions": batch }))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                if failing {
                    log::info!("Console link: relay session reports going through again");
                }
                failing = false;
                continue;
            }
            if !failing {
                log::warn!("Console link: relay session report failed, retrying");
            }
            failing = true;
            // Back in front, in order, for the next round.
            if let Ok(mut p) = PENDING.lock() {
                let mut kept = batch;
                kept.append(&mut p);
                if kept.len() > MAX_PENDING {
                    kept.drain(..kept.len() - MAX_PENDING);
                }
                *p = kept;
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ipv4_mapped_addresses_are_reported_as_ipv4() {
        ON.store(true, Ordering::SeqCst);
        let s = opened(
            "m1",
            ("123456789", 0, addr("[::ffff:10.0.0.1]:5000")),
            ("", 0, addr("[2001:db8::2]:6000")),
        )
        .expect("reported");
        assert_eq!(s.controller_ip, "10.0.0.1");
        assert_eq!(s.device_ip, "2001:db8::2");
        PENDING.lock().unwrap().clear();
    }

    #[test]
    fn the_side_that_names_a_device_is_the_controller() {
        ON.store(true, Ordering::SeqCst);
        let s = opened(
            "u1",
            ("", 0, addr("10.0.0.2:5000")),
            ("123456789", 1, addr("10.0.0.1:6000")),
        )
        .expect("reported");
        assert_eq!(s.id, "123456789");
        assert_eq!(s.conn_type, 1);
        assert_eq!(s.controller_ip, "10.0.0.1");
        assert_eq!(s.device_ip, "10.0.0.2");

        let s = opened(
            "u2",
            ("987654321", 5, addr("10.0.0.3:5000")),
            ("", 0, addr("10.0.0.4:6000")),
        )
        .expect("reported");
        assert_eq!((s.id.as_str(), s.conn_type), ("987654321", 5));
        assert_eq!(s.controller_ip, "10.0.0.3");

        assert!(opened("u3", ("", 0, addr("10.0.0.5:1")), ("", 0, addr("10.0.0.6:1"))).is_none());
        PENDING.lock().unwrap().clear();
    }
}
