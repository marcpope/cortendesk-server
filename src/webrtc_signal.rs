// Part of CortenDesk Server, a modified version of rustdesk-server distributed
// under the AGPL-3.0. Added on 2026-11-01. See CHANGES.md.

//! WebRTC signalling routes (RustDesk 1.5).
//!
//! A 1.5 client that wants WebRTC puts an SDP offer in its punch hole request.
//! `hbbs` hands the offer to the device in `PunchHole`, the device's answer
//! comes back in `PunchHoleSent` or `RelayResponse`, and both sides then
//! trickle `IceCandidate` messages through `hbbs` until a connection forms:
//!
//! - controller to device: on the controller's request connection, addressed
//!   by the device `id`, forwarded like `PunchHole`;
//! - device to controller: on a connection of the device's own, addressed by
//!   the controller's `socket_addr`, written to the controller's request
//!   connection.
//!
//! So the controller's connection has to outlive the first reply, which
//! normally consumes it. A route records that a connection carried an offer to
//! a given device, keeps its sink for the length of the exchange, and bounds
//! what may be sent along it. Only connections that opened a route can send
//! candidates to a device, only to that device, and only routes can receive
//! candidates, so neither direction can be aimed at an arbitrary address.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

/// How long a route lives. The client gives the whole exchange its 18 second
/// connect timeout, three punch attempts included; this is that with room.
pub const ROUTE_TTL: Duration = Duration::from_secs(60);
/// Routes held at once. A new offer past this goes on without WebRTC.
pub const MAX_ROUTES: usize = 4096;
/// Routes held at once for one IP, so a single host cannot use them all up.
pub const MAX_ROUTES_PER_IP: usize = 64;
/// Messages per route and direction: candidates, and towards the controller
/// also the answer and any other reply. A machine gathers one host candidate
/// per interface address plus a few reflexive and relay ones; clients cap
/// their own queues at 64.
pub const MAX_CANDIDATES: u32 = 64;
/// An offer or answer: a base64 envelope around an SDP of about a kilobyte.
/// Kept well under a UDP datagram, which carries the offer to the device.
pub const MAX_SDP_LEN: usize = 16 * 1024;
/// One `a=candidate` line.
pub const MAX_CANDIDATE_LEN: usize = 2048;
/// The session key is the DTLS fingerprint of the offer.
pub const MAX_SESSION_KEY_LEN: usize = 256;

pub struct Route<S> {
    peer_id: String,
    expires: Instant,
    to_peer: u32,
    to_controller: u32,
    /// The controller's connection, once something has been sent to it.
    pub sink: Option<S>,
}

pub struct Routes<S> {
    map: HashMap<SocketAddr, Route<S>>,
}

impl<S> Default for Routes<S> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

impl<S> Routes<S> {
    /// Open or renew the route for a controller connection offering to
    /// `peer_id`. A retry of the same request renews it; an offer to another
    /// device from the same connection replaces it. False when full.
    pub fn open(&mut self, addr: SocketAddr, peer_id: &str, now: Instant) -> bool {
        if let Some(route) = self.map.get_mut(&addr) {
            if route.peer_id == peer_id {
                route.expires = now + ROUTE_TTL;
                return true;
            }
            self.map.remove(&addr);
        }
        let same_ip = |map: &HashMap<SocketAddr, Route<S>>| map.keys().filter(|a| a.ip() == addr.ip()).count();
        if self.map.len() >= MAX_ROUTES || same_ip(&self.map) >= MAX_ROUTES_PER_IP {
            self.map.retain(|_, r| r.expires > now);
            if self.map.len() >= MAX_ROUTES || same_ip(&self.map) >= MAX_ROUTES_PER_IP {
                return false;
            }
        }
        self.map.insert(
            addr,
            Route {
                peer_id: peer_id.to_owned(),
                expires: now + ROUTE_TTL,
                to_peer: 0,
                to_controller: 0,
                sink: None,
            },
        );
        true
    }

    /// The live route for a controller connection, dropping it if expired.
    pub fn get(&mut self, addr: SocketAddr, now: Instant) -> Option<&mut Route<S>> {
        if self.map.get(&addr).is_some_and(|r| r.expires <= now) {
            self.map.remove(&addr);
        }
        self.map.get_mut(&addr)
    }

    pub fn contains(&mut self, addr: SocketAddr, now: Instant) -> bool {
        self.get(addr, now).is_some()
    }

    /// May the connection at `addr` send a candidate to `peer_id`?
    pub fn allow_to_peer(&mut self, addr: SocketAddr, peer_id: &str, now: Instant) -> bool {
        match self.get(addr, now) {
            Some(r) if r.peer_id == peer_id && r.to_peer < MAX_CANDIDATES => {
                r.to_peer += 1;
                true
            }
            _ => false,
        }
    }

    /// May a candidate be delivered to the controller at `addr`?
    pub fn allow_to_controller(&mut self, addr: SocketAddr, now: Instant) -> bool {
        match self.get(addr, now) {
            Some(r) if r.to_controller < MAX_CANDIDATES => {
                r.to_controller += 1;
                true
            }
            _ => false,
        }
    }

    /// The controller's connection closed.
    pub fn close(&mut self, addr: SocketAddr) -> Option<Route<S>> {
        self.map.remove(&addr)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    #[test]
    fn only_the_offering_connection_reaches_only_its_device() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        assert!(r.open(addr(1), "123456789", now));
        assert!(r.allow_to_peer(addr(1), "123456789", now));
        assert!(!r.allow_to_peer(addr(1), "987654321", now));
        assert!(!r.allow_to_peer(addr(2), "123456789", now));
        assert!(r.allow_to_controller(addr(1), now));
        assert!(!r.allow_to_controller(addr(2), now));
    }

    #[test]
    fn candidates_are_capped_per_direction() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        r.open(addr(1), "1", now);
        for _ in 0..MAX_CANDIDATES {
            assert!(r.allow_to_peer(addr(1), "1", now));
            assert!(r.allow_to_controller(addr(1), now));
        }
        assert!(!r.allow_to_peer(addr(1), "1", now));
        assert!(!r.allow_to_controller(addr(1), now));
    }

    #[test]
    fn a_retry_renews_and_keeps_the_sink() {
        let now = Instant::now();
        let mut r = Routes::<u8>::default();
        r.open(addr(1), "1", now);
        r.get(addr(1), now).unwrap().sink = Some(7);
        let later = now + ROUTE_TTL - Duration::from_secs(1);
        assert!(r.open(addr(1), "1", later));
        let r1 = r.get(addr(1), later + Duration::from_secs(5)).unwrap();
        assert_eq!(r1.sink, Some(7));
    }

    #[test]
    fn an_offer_to_another_device_replaces_the_route() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        r.open(addr(1), "1", now);
        r.open(addr(1), "2", now);
        assert!(!r.allow_to_peer(addr(1), "1", now));
        assert!(r.allow_to_peer(addr(1), "2", now));
    }

    #[test]
    fn routes_expire() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        r.open(addr(1), "1", now);
        assert!(!r.contains(addr(1), now + ROUTE_TTL));
        assert!(!r.allow_to_controller(addr(1), now + ROUTE_TTL));
    }

    #[test]
    fn one_ip_cannot_take_every_route() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        for port in 0..MAX_ROUTES_PER_IP as u16 {
            assert!(r.open(addr(port), "1", now));
        }
        assert!(!r.open(addr(60000), "1", now));
        assert!(r.open(SocketAddr::from(([198, 51, 100, 9], 1)), "1", now));
        assert!(r.open(addr(60000), "1", now + ROUTE_TTL));
    }

    #[test]
    fn a_full_table_drops_expired_routes_before_refusing() {
        let now = Instant::now();
        let mut r = Routes::<()>::default();
        for i in 0..MAX_ROUTES {
            assert!(r.open(SocketAddr::from(([10, 0, (i >> 8) as u8, i as u8], 1)), "1", now));
        }
        assert!(!r.open(addr(1), "1", now));
        assert!(r.open(addr(1), "1", now + ROUTE_TTL));
        assert_eq!(r.len(), 1);
    }
}
