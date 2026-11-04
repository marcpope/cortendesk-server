// Modified by the CortenDesk Server project on 2026-11-03: registration over a
// persistent TCP or WebSocket stream (`Peer::stream`), based on PR #1 by
// vk2amv. Modified on 2026-11-04: `MAX_PEER_ID_LEN`; `PeerMap::release`;
// pruning of idle peers and expired per-IP entries (`PeerMap::prune`). See
// CHANGES.md. This file is part of a modified version of rustdesk-server,
// distributed under the AGPL-3.0 like the original.

use crate::common::*;
use crate::database;
use crate::stream_connection::Registration;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

pub(crate) type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
pub(crate) type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
/// A cached peer idle this long is dropped from memory; the database keeps it
/// and `PeerMap::get` loads it again (issue #10). Idle: no stream
/// registration, no UDP registration or `RegisterPk` for that long, and held
/// by nobody else. Far longer than UDP presence (30 seconds) and the access
/// policy's address match, which keeps its own record (`policy::SEEN`).
pub const PEER_IDLE_SECS: u64 = 600;
/// Most client IPs tracked for the per-IP registration limits. Past it, after
/// dropping expired entries, a new IP registers untracked rather than being
/// refused: refusing would let a flood of spoofed UDP sources lock everyone
/// new out for a day.
pub const MAX_IP_BLOCKER_ENTRIES: usize = 1_000_000;
/// Most addresses kept per ID for the `ip-changes` admin command.
pub const MAX_IP_CHANGES_PER_ID: usize = 128;
/// Longest peer ID accepted, in bytes. Every peer entry and punch request
/// record keeps its own copy, and a real ID is far shorter.
pub const MAX_PEER_ID_LEN: usize = 253;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) stream: Option<Registration>,
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            stream: None,
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

impl Peer {
    pub(crate) fn endpoint(&self) -> Option<(SocketAddr, bool)> {
        if let Some(stream) = self.stream.as_ref().filter(|s| s.alive()) {
            return Some((stream.connection.addr, stream.connection.ws));
        }
        if self.socket_addr.port() != 0 && self.last_reg_time.elapsed().as_secs() < 30 {
            return Some((self.socket_addr, false));
        }
        None
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = get_arg_opt("DB_URL").unwrap_or_else(|| {
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?}", id, addr);
        // Commit identity to memory only after persistence succeeds. Presence is
        // maintained by the caller separately for UDP and registered streams.
        let guid = peer.read().await.guid.clone();
        let info = PeerInfo { ip };
        let info_str = match serde_json::to_string(&info) {
            Ok(value) => value,
            Err(_) => return register_pk_response::Result::SERVER_ERROR,
        };
        let guid = if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Ok(guid) => guid,
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            guid
        };
        let mut peer = peer.write().await;
        peer.guid = guid;
        peer.uuid = uuid;
        peer.pk = pk;
        peer.info = info;
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            // Another task may have loaded/registered this ID while the DB
            // read was in flight. Never replace its live connection ownership.
            let peer = self
                .map
                .write()
                .await
                .entry(id.to_owned())
                .or_insert(peer)
                .clone();
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    /// Forget `id`, in the database and in memory, and close its stream
    /// registration if it has one, so another machine can register it.
    /// `None` when there was nothing to forget, else whether it was online.
    pub(crate) async fn release(&self, id: &str) -> ResultType<Option<bool>> {
        let deleted = self.db.delete_peer(id).await?;
        let removed = self.map.write().await.remove(id);
        let mut online = false;
        if let Some(peer) = removed.as_ref() {
            let mut peer = peer.write().await;
            online = peer.endpoint().is_some();
            if let Some(registration) = peer.stream.take() {
                registration.connection.close();
            }
        }
        Ok((deleted || removed.is_some()).then_some(online))
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    /// Drop idle peers from memory and expired entries from the per-IP
    /// registration limits and the IP change log. Run every minute.
    pub(crate) async fn prune(&self) {
        let peers = prune_peers(&mut *self.map.write().await);
        let ips = prune_ip_blocker(&mut *IP_BLOCKER.lock().await);
        let changes = prune_ip_changes(&mut *IP_CHANGES.lock().await);
        if peers + ips + changes > 0 {
            log::debug!("Pruned {peers} idle peers, {ips} IP limit and {changes} IP change entries");
        }
    }
}

fn peer_is_idle(peer: &Peer) -> bool {
    peer.stream.is_none()
        && peer.last_reg_time.elapsed().as_secs() >= PEER_IDLE_SECS
        && peer.reg_pk.1.elapsed().as_secs() >= PEER_IDLE_SECS
}

/// A peer someone else holds (a registration or request in progress) or that
/// is locked is kept for the next round.
fn prune_peers(map: &mut HashMap<String, LockPeer>) -> usize {
    let before = map.len();
    map.retain(|_, peer| {
        Arc::strong_count(peer) > 1 || peer.try_read().map_or(true, |p| !peer_is_idle(&p))
    });
    before - map.len()
}

pub(crate) fn prune_ip_blocker(map: &mut IpBlockMap) -> usize {
    let before = map.len();
    map.retain(|_, (burst, ids)| {
        burst.1.elapsed().as_secs() <= IP_BLOCK_DUR || ids.1.elapsed().as_secs() <= DAY_SECONDS
    });
    before - map.len()
}

fn prune_ip_changes(map: &mut IpChangesMap) -> usize {
    let before = map.len();
    map.retain(|_, (tm, _)| tm.elapsed().as_secs() < IP_CHANGE_DUR_X2);
    before - map.len()
}

/// The per-IP registration limits: `max_burst` registrations without a pause
/// of `IP_BLOCK_DUR`, and `max_ids` distinct IDs a day. At most `max_ips` IPs
/// are tracked; see `MAX_IP_BLOCKER_ENTRIES`.
pub(crate) fn ip_blocker_allows(
    map: &mut IpBlockMap,
    ip: &str,
    id: &str,
    max_burst: u32,
    max_ids: usize,
    max_ips: usize,
) -> bool {
    if !map.contains_key(ip) && map.len() >= max_ips {
        prune_ip_blocker(map);
        if map.len() >= max_ips {
            static WARNED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let minute = now() / 60;
            if WARNED.swap(minute, std::sync::atomic::Ordering::Relaxed) != minute {
                log::warn!("Per-IP registration limits track {max_ips} IPs already; {ip} is not tracked");
            }
            return true;
        }
    }
    let now = Instant::now();
    let old = map
        .entry(ip.to_owned())
        .or_insert_with(|| ((0, now), (Default::default(), now)));
    let counter = &mut old.0;
    if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
        counter.0 = 0;
    }
    if counter.0 >= max_burst {
        return false;
    }
    counter.0 += 1;
    counter.1 = now;

    let counter = &mut old.1;
    let is_new = counter.0.get(id).is_none();
    if counter.1.elapsed().as_secs() > DAY_SECONDS {
        counter.0.clear();
    }
    if counter.0.len() >= max_ids {
        return !is_new;
    }
    if is_new {
        counter.0.insert(id.to_owned());
    }
    counter.1 = now;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ago(secs: u64) -> Instant {
        Instant::now() - Duration::from_secs(secs)
    }

    fn peer(last_reg: u64, reg_pk: u64) -> LockPeer {
        Arc::new(RwLock::new(Peer {
            last_reg_time: ago(last_reg),
            reg_pk: (1, ago(reg_pk)),
            ..Default::default()
        }))
    }

    #[test]
    fn pruning_keeps_live_and_held_peers() {
        let mut map = HashMap::new();
        map.insert("idle".to_owned(), peer(3600, 3600));
        map.insert("udp-online".to_owned(), peer(5, 3600));
        map.insert("udp-9-minutes".to_owned(), peer(540, 3600));
        map.insert("registered-just-now".to_owned(), peer(3600, 5));
        // A WebSocket or TCP registration: kept however long since UDP.
        let streamed = peer(3600, 3600);
        let (connection, _rx, _stop) =
            crate::stream_connection::Connection::new("192.0.2.1:5".parse().unwrap(), true);
        streamed.try_write().unwrap().stream = Some(Registration {
            connection,
            last_seen: ago(3600),
        });
        map.insert("streamed".to_owned(), streamed);
        // Held by a request in progress.
        let held = peer(3600, 3600);
        map.insert("held".to_owned(), held.clone());

        assert_eq!(prune_peers(&mut map), 1);
        assert!(!map.contains_key("idle"));
        for id in ["udp-online", "udp-9-minutes", "registered-just-now", "streamed", "held"] {
            assert!(map.contains_key(id), "{id}");
        }
        drop(held);
        assert_eq!(prune_peers(&mut map), 1);
        assert!(!map.contains_key("held"));
    }

    /// Pruning the peer cache leaves the access policy's address match alone:
    /// it keeps its own record of who registered from where.
    #[test]
    fn pruning_peers_keeps_the_policy_address_match() {
        let ip: std::net::IpAddr = "198.51.100.40".parse().unwrap();
        crate::policy::note_registration("prune-policy-a", ip);
        let mut map = HashMap::new();
        map.insert("prune-policy-a".to_owned(), peer(3600, 3600));
        assert_eq!(prune_peers(&mut map), 1);
        assert_eq!(crate::policy::candidates(ip, "prune-policy-b"), vec!["prune-policy-a"]);
        // And an entry inside the policy's window is never idle here.
        assert!(PEER_IDLE_SECS > 2 * 30);
    }

    #[test]
    fn ip_limits_expire_and_stay_bounded() {
        let mut map = IpBlockMap::new();
        map.insert("192.0.2.1".to_owned(), ((3, ago(120)), (HashSet::from(["a".to_owned()]), ago(DAY_SECONDS + 10))));
        map.insert("192.0.2.2".to_owned(), ((3, ago(120)), (HashSet::from(["a".to_owned()]), ago(60))));
        assert_eq!(prune_ip_blocker(&mut map), 1);
        assert!(map.contains_key("192.0.2.2"));

        // Full: a new IP is let through untracked, known IPs are still limited.
        let mut map = IpBlockMap::new();
        assert!(ip_blocker_allows(&mut map, "192.0.2.10", "id1", 2, 300, 1));
        assert!(ip_blocker_allows(&mut map, "192.0.2.11", "id2", 2, 300, 1));
        assert!(ip_blocker_allows(&mut map, "192.0.2.11", "id2", 2, 300, 1));
        assert_eq!(map.len(), 1);
        assert!(ip_blocker_allows(&mut map, "192.0.2.10", "id1", 2, 300, 1));
        assert!(!ip_blocker_allows(&mut map, "192.0.2.10", "id1", 2, 300, 1));
        // An expired entry makes room.
        map.get_mut("192.0.2.10").unwrap().0 .1 = ago(120);
        map.get_mut("192.0.2.10").unwrap().1 .1 = ago(DAY_SECONDS + 10);
        assert!(ip_blocker_allows(&mut map, "192.0.2.11", "id2", 2, 300, 1));
        assert!(map.contains_key("192.0.2.11"));
    }

    #[test]
    fn ip_changes_expire() {
        let mut map = IpChangesMap::new();
        map.insert("old".to_owned(), (ago(IP_CHANGE_DUR_X2 + 1), HashMap::new()));
        map.insert("new".to_owned(), (ago(10), HashMap::new()));
        assert_eq!(prune_ip_changes(&mut map), 1);
        assert!(map.contains_key("new"));
    }
}
