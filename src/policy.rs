// Added by the CortenDesk Server project on 2026-09-29. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

//! Device access policy from a CortenDesk console, and LAN address reports
//! back to it.
//!
//! The console decides which devices may use this server. hbbs pulls that
//! decision as a snapshot every few seconds and enforces it from memory, so no
//! signalling request waits on HTTP. Nothing here runs unless both
//! `CORTENDESK_CONSOLE_URL` and `CORTENDESK_SERVER_SECRET` are set.
//!
//! Who is asking: a punch hole or relay request names only the target. The
//! initiator is identified, in order, by a console-signed web client ticket in
//! `token`, by the client's console access token (`token`, sent by signed-in
//! clients), or by its public IP matched against peers registered from that IP
//! in the last 30 seconds.

use hbb_common::{log, tokio};
use serde_derive::{Deserialize, Serialize};
use sodiumoxide::crypto::{auth::hmacsha256, hash::sha256};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Last good snapshot, kept in the working directory next to the key pair so a
/// restart with the console down still enforces it.
const SNAPSHOT_FILE: &str = "policy_snapshot.json";
/// A peer counts as registered from an IP for this long. Matches REG_TIMEOUT.
const REG_WINDOW: Duration = Duration::from_secs(30);
/// Report an unchanged LAN address again only after this long.
const LOCAL_ADDR_RESEND: Duration = Duration::from_secs(600);
const MAX_PENDING_REPORTS: usize = 5000;
const TICKET_PREFIX: &str = "cdw1";

pub const DENY_UNAPPROVED: &str =
    "This device is not approved on this server, so it cannot start sessions. Ask your administrator to approve it.";
pub const DENY_INCOMING_ONLY: &str =
    "This device is set to incoming only. It can be controlled but cannot start sessions.";
pub const DENY_TARGET: &str = "The remote device is not approved on this server.";

/// What the console sends. Mode "approved" means only approved devices may
/// use signalling; anything else is open.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub mode: String,
    /// Approved devices that may start sessions.
    #[serde(default)]
    pub allow: HashSet<String>,
    /// Approved devices that may only receive sessions.
    #[serde(default)]
    pub incoming_only: HashSet<String>,
    /// sha256 hex of a console access token -> the device it was issued to.
    #[serde(default)]
    pub tokens: HashMap<String, String>,
    /// Approved-only mode: may a signed-out initiator be matched to a device
    /// by the IP it registered from? Off unless the console turns it on,
    /// because a shared public IP or a proxy that rewrites source addresses
    /// (Docker's userland proxy, IPv6 port publishing) makes every client
    /// look like every other one behind it.
    #[serde(default)]
    pub ip_match: bool,
}

impl Snapshot {
    fn strict(&self) -> bool {
        self.mode == "approved"
    }

    fn approved(&self, id: &str) -> bool {
        self.allow.contains(id) || self.incoming_only.contains(id)
    }

    fn may_initiate(&self, id: &str) -> bool {
        if self.strict() {
            self.allow.contains(id)
        } else {
            !self.incoming_only.contains(id)
        }
    }

    fn denial_for(&self, id: &str) -> &'static str {
        if self.incoming_only.contains(id) {
            DENY_INCOMING_ONLY
        } else {
            DENY_UNAPPROVED
        }
    }
}

#[derive(Default)]
struct State {
    secret: String,
    snapshot: Option<Arc<Snapshot>>,
    etag: String,
    pulled_at: Option<Instant>,
}

#[derive(Default)]
struct Seen {
    by_ip: HashMap<IpAddr, HashMap<String, Instant>>,
    by_id: HashMap<String, IpAddr>,
}

#[derive(Default)]
struct Reports {
    pending: HashMap<String, (IpAddr, u64)>,
    sent: HashMap<String, (IpAddr, Instant)>,
}

lazy_static::lazy_static! {
    static ref STATE: RwLock<State> = Default::default();
    static ref SEEN: Mutex<Seen> = Default::default();
    static ref REPORTS: Mutex<Reports> = Default::default();
}

fn norm(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn snapshot() -> Option<Arc<Snapshot>> {
    STATE.read().ok()?.snapshot.clone()
}

/// A peer finished registering from `ip`.
pub fn note_registration(id: &str, ip: IpAddr) {
    let ip = norm(ip);
    let Ok(mut seen) = SEEN.lock() else { return };
    if let Some(old) = seen.by_id.insert(id.to_owned(), ip) {
        if old != ip {
            if let Some(ids) = seen.by_ip.get_mut(&old) {
                ids.remove(id);
            }
        }
    }
    seen.by_ip
        .entry(ip)
        .or_default()
        .insert(id.to_owned(), Instant::now());
}

/// Peers registered from `ip` recently, not counting `target`: a device never
/// connects to itself, so the target cannot be the one asking.
fn candidates(ip: IpAddr, target: &str) -> Vec<String> {
    let Ok(seen) = SEEN.lock() else { return vec![] };
    seen.by_ip
        .get(&norm(ip))
        .map(|ids| {
            ids.iter()
                .filter(|(id, tm)| id.as_str() != target && tm.elapsed() < REG_WINDOW)
                .map(|(id, _)| id.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn prune_seen() {
    let Ok(mut seen) = SEEN.lock() else { return };
    let keep = REG_WINDOW * 2;
    seen.by_ip.retain(|_, ids| {
        ids.retain(|_, tm| tm.elapsed() < keep);
        !ids.is_empty()
    });
    let Seen { by_ip, by_id } = &mut *seen;
    by_id.retain(|id, ip| by_ip.get(ip).map_or(false, |ids| ids.contains_key(id)));
}

/// A console-signed ticket for its own web client: `cdw1.<expiry>.<subject>.<hmac>`.
fn ticket_valid(token: &str, secret: &str) -> bool {
    if secret.is_empty() || !token.starts_with(TICKET_PREFIX) {
        return false;
    }
    let Some((signed, sig)) = token.rsplit_once('.') else { return false };
    let mut parts = signed.split('.');
    if parts.next() != Some(TICKET_PREFIX) {
        return false;
    }
    let Some(expiry) = parts.next().and_then(|x| x.parse::<u64>().ok()) else {
        return false;
    };
    if expiry < now_secs() {
        return false;
    }
    let mut state = hmacsha256::State::init(secret.as_bytes());
    state.update(signed.as_bytes());
    // Tag comparison is constant time.
    hmacsha256::Tag::from_slice(&unhex(sig)) == Some(state.finalize())
}

fn unhex(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        return vec![];
    }
    (0..s.len())
        .step_by(2)
        .map_while(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// May the sender of a punch hole or relay request for `target` start a
/// session? `ip` is the TCP peer address, never a forwarded header.
pub fn check_initiator(token: &str, ip: IpAddr, target: &str) -> Result<(), &'static str> {
    let (snap, secret) = match STATE.read() {
        Ok(state) => match &state.snapshot {
            Some(snap) => (snap.clone(), state.secret.clone()),
            None => return Ok(()),
        },
        Err(_) => return Ok(()),
    };
    if !token.is_empty() {
        if ticket_valid(token, &secret) {
            return Ok(());
        }
        if let Some(id) = snap.tokens.get(&hex(&sha256::hash(token.as_bytes()).0)) {
            return if snap.may_initiate(id) {
                Ok(())
            } else {
                Err(snap.denial_for(id))
            };
        }
    }
    let ids = if snap.strict() && !snap.ip_match {
        vec![]
    } else {
        candidates(ip, target)
    };
    if ids.iter().any(|id| snap.may_initiate(id)) {
        return Ok(());
    }
    match ids.first() {
        Some(id) => Err(snap.denial_for(id)),
        None if snap.strict() => Err(DENY_UNAPPROVED),
        None => Ok(()),
    }
}

/// May `target` receive a session? Only restricted in approved-only mode.
pub fn check_target(target: &str) -> Result<(), &'static str> {
    match snapshot() {
        Some(snap) if snap.strict() && !snap.approved(target) => Err(DENY_TARGET),
        _ => Ok(()),
    }
}

/// A peer answered FetchLocalAddr. Queued for the console when it comes from
/// the IP that peer registered from, and is new or not reported lately.
pub fn note_local_addr(id: &str, local_addr: SocketAddr, from: IpAddr) {
    let lan = norm(local_addr.ip());
    if id.is_empty() || lan.is_unspecified() || lan.is_loopback() {
        return;
    }
    let registered = SEEN.lock().ok().and_then(|s| s.by_id.get(id).copied());
    if registered != Some(norm(from)) {
        return;
    }
    let Ok(mut reports) = REPORTS.lock() else { return };
    if let Some((ip, tm)) = reports.sent.get(id) {
        if *ip == lan && tm.elapsed() < LOCAL_ADDR_RESEND {
            return;
        }
    }
    if reports.pending.len() < MAX_PENDING_REPORTS || reports.pending.contains_key(id) {
        reports.pending.insert(id.to_owned(), (lan, now_secs()));
    }
}

/// One line for the `policy` admin command.
pub fn describe() -> String {
    let Ok(state) = STATE.read() else { return String::new() };
    match &state.snapshot {
        None if state.secret.is_empty() => "console link off\n".to_owned(),
        None => "no policy yet: every device allowed\n".to_owned(),
        Some(s) => format!(
            "mode={} allow={} incoming_only={} tokens={} ip_match={} last_pull={}\n",
            if s.strict() { "approved" } else { "open" },
            s.allow.len(),
            s.incoming_only.len(),
            s.tokens.len(),
            s.ip_match,
            state
                .pulled_at
                .map(|t| format!("{}s ago", t.elapsed().as_secs()))
                .unwrap_or_else(|| "never (cached)".to_owned()),
        ),
    }
}

fn install(snap: Snapshot, etag: String, pulled: bool) {
    let summary = format!(
        "mode={} allow={} incoming_only={}",
        if snap.strict() { "approved" } else { "open" },
        snap.allow.len(),
        snap.incoming_only.len()
    );
    if let Ok(mut state) = STATE.write() {
        let changed = state
            .snapshot
            .as_ref()
            .map_or(true, |old| old.mode != snap.mode);
        state.snapshot = Some(Arc::new(snap));
        state.etag = etag;
        if pulled {
            state.pulled_at = Some(Instant::now());
        }
        if changed {
            log::info!("Policy: {summary}");
        }
    }
}

fn save_cache(body: &str) {
    let tmp = format!("{SNAPSHOT_FILE}.tmp");
    let res = std::fs::write(&tmp, body).and_then(|_| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, SNAPSHOT_FILE)
    });
    if let Err(err) = res {
        log::warn!("Policy: could not save {SNAPSHOT_FILE}: {err}");
    }
}

/// Start the console link if it is configured. Call from inside the runtime.
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
        log::info!("Console link off: set CORTENDESK_CONSOLE_URL and CORTENDESK_SERVER_SECRET to enforce device policy");
        return;
    }
    let interval = crate::common::get_arg_opt("CORTENDESK_POLICY_INTERVAL")
        .and_then(|x| x.trim().parse::<u64>().ok())
        .unwrap_or(5)
        .clamp(1, 300);
    if let Ok(mut state) = STATE.write() {
        state.secret = secret.clone();
    }
    match std::fs::read_to_string(SNAPSHOT_FILE)
        .ok()
        .and_then(|body| serde_json::from_str::<Snapshot>(&body).ok())
    {
        Some(snap) => {
            log::info!("Policy: using the cached snapshot until the console answers");
            install(snap, String::new(), false);
        }
        None => log::warn!(
            "Policy: none yet. Every device is allowed until the console at {url} answers"
        ),
    }
    log::info!("Console link: {url}, policy every {interval}s");
    tokio::spawn(run(url, secret, Duration::from_secs(interval)));
}

async fn run(url: String, secret: String, every: Duration) {
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
        match pull(&client, &url, &secret).await {
            Ok(()) => {
                if failing {
                    log::info!("Console link: reachable again");
                }
                failing = false;
            }
            Err(err) => {
                if !failing {
                    log::warn!("Console link: policy pull failed, keeping the last policy: {err}");
                }
                failing = true;
            }
        }
        report(&client, &url, &secret).await;
        prune_seen();
        tokio::time::sleep(every).await;
    }
}

async fn pull(client: &reqwest::Client, url: &str, secret: &str) -> Result<(), String> {
    let etag = STATE.read().map(|s| s.etag.clone()).unwrap_or_default();
    let mut req = client
        .get(format!("{url}/api/server/policy"))
        .bearer_auth(secret);
    if !etag.is_empty() {
        req = req.header("If-None-Match", etag);
    }
    let res = req.send().await.map_err(|e| e.to_string())?;
    let status = res.status();
    if status == reqwest::StatusCode::NOT_MODIFIED {
        if let Ok(mut state) = STATE.write() {
            state.pulled_at = Some(Instant::now());
        }
        return Ok(());
    }
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = res.text().await.map_err(|e| e.to_string())?;
    let snap: Snapshot = serde_json::from_str(&body).map_err(|e| format!("bad policy: {e}"))?;
    save_cache(&body);
    install(snap, etag, true);
    Ok(())
}

#[derive(Serialize)]
struct AddrReport {
    id: String,
    ip: String,
    seen_at: u64,
}

async fn report(client: &reqwest::Client, url: &str, secret: &str) {
    let batch: Vec<(String, IpAddr, u64)> = match REPORTS.lock() {
        Ok(mut r) => r
            .pending
            .drain()
            .map(|(id, (ip, at))| (id, ip, at))
            .collect(),
        Err(_) => return,
    };
    if batch.is_empty() {
        return;
    }
    let addrs: Vec<AddrReport> = batch
        .iter()
        .map(|(id, ip, at)| AddrReport {
            id: id.clone(),
            ip: ip.to_string(),
            seen_at: *at,
        })
        .collect();
    let ok = client
        .post(format!("{url}/api/server/local-addrs"))
        .bearer_auth(secret)
        .json(&serde_json::json!({ "addrs": addrs }))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    let Ok(mut reports) = REPORTS.lock() else { return };
    for (id, ip, at) in batch {
        if ok {
            reports.sent.insert(id, (ip, Instant::now()));
        } else if reports.pending.len() < MAX_PENDING_REPORTS {
            // Keep it for the next round unless a newer address arrived.
            reports.pending.entry(id).or_insert((ip, at));
        }
    }
    if !ok {
        log::debug!("Console link: LAN address report failed, retrying next round");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &str, signed: &str) -> String {
        let mut state = hmacsha256::State::init(secret.as_bytes());
        state.update(signed.as_bytes());
        hex(&state.finalize().0)
    }

    #[test]
    fn web_ticket_checks_signature_and_expiry() {
        let exp = now_secs() + 60;
        let signed = format!("cdw1.{exp}.web-1");
        let good = format!("{signed}.{}", sign("s3cret", &signed));
        assert!(ticket_valid(&good, "s3cret"));
        assert!(!ticket_valid(&good, "other"));
        assert!(!ticket_valid(&good, ""));
        assert!(!ticket_valid(&good.replace("web-1", "web-2"), "s3cret"));

        let old = format!("cdw1.{}.web-1", now_secs() - 1);
        assert!(!ticket_valid(&format!("{old}.{}", sign("s3cret", &old)), "s3cret"));
        assert!(!ticket_valid("cdw1.garbage", "s3cret"));
        assert!(!ticket_valid("an-ordinary-access-token", "s3cret"));
    }

    #[test]
    fn open_mode_only_stops_incoming_only_devices() {
        let snap = Snapshot {
            mode: "open".into(),
            incoming_only: ["kiosk".to_owned()].into(),
            ..Default::default()
        };
        assert!(snap.may_initiate("anyone"));
        assert!(!snap.may_initiate("kiosk"));
        assert!(snap.approved("kiosk"));
    }

    #[test]
    fn approved_mode_needs_the_allow_list() {
        let snap = Snapshot {
            mode: "approved".into(),
            allow: ["desk".to_owned()].into(),
            incoming_only: ["kiosk".to_owned()].into(),
            ..Default::default()
        };
        assert!(snap.may_initiate("desk"));
        assert!(!snap.may_initiate("kiosk"));
        assert!(!snap.may_initiate("stranger"));
        assert!(snap.approved("kiosk"));
        assert!(!snap.approved("stranger"));
        assert_eq!(snap.denial_for("kiosk"), DENY_INCOMING_ONLY);
        assert_eq!(snap.denial_for("stranger"), DENY_UNAPPROVED);
    }

    #[test]
    fn ipv4_mapped_addresses_match_plain_ipv4() {
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        let plain: IpAddr = "10.1.2.3".parse().unwrap();
        note_registration("unit-peer-a", mapped);
        assert_eq!(candidates(plain, "someone-else"), vec!["unit-peer-a".to_owned()]);
        assert!(candidates(plain, "unit-peer-a").is_empty());
    }
}
