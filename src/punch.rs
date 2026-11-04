// Added by the CortenDesk Server project on 2026-11-04. See CHANGES.md.
// This file is part of a modified version of rustdesk-server, distributed under
// the AGPL-3.0 like the original.

//! UDP hole punching and IPv6 peer-to-peer for RustDesk 1.5 (issue #18).
//!
//! A punch route records one controller connection whose request was granted
//! `udp_port` or `socket_addr_v6`. It is keyed by that connection's address
//! (the `tcp_punch` key) and is the only thing that lets a reply from the
//! device carry a UDP address or an IPv6 address back. Everything here is
//! bounded; see the constants.

use crate::common::norm_ip;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

/// How long a route waits for the device's reply.
pub const ROUTE_TTL: Duration = Duration::from_secs(30);
/// Routes in all, and per controller IP (IPv6: per /64).
pub const MAX_ROUTES: usize = 10_000;
pub const MAX_ROUTES_PER_IP: usize = 64;
/// UDP `TestNatRequest` answers, per source IP (IPv6: per /64): a client's
/// test sends 5 to 7, and several clients can share one public IP.
pub const NAT_TEST_BURST: f64 = 60.;
pub const NAT_TEST_RATE: f64 = 30.;
/// UDP `TestNatRequest` answers in all, per second, burst twice that.
pub const NAT_TEST_GLOBAL_RATE: f64 = 2_000.;
/// IPv6 addresses handed on, per controller IP and per target /64.
pub const V6_BURST: f64 = 60.;
pub const V6_RATE: f64 = 1.;
/// Entries in each limiter table. A full table refuses sources it does not
/// know yet, after dropping the idle ones.
pub const MAX_LIMITER_ENTRIES: usize = 65_536;
/// Devices known to run a client before 1.5, which gets no UDP port or IPv6
/// address: it would punch with probes a 1.5 controller does not answer.
pub const MAX_OLD_CLIENTS: usize = 100_000;
const OLD_CLIENT_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// The rate limiter key of an address: the IPv4 address, or the IPv6 /64.
pub fn ip_key(ip: IpAddr) -> IpAddr {
    match norm_ip(ip) {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}

/// Whether `a` and `b` are the same host as far as replies go: equal IPv4
/// addresses, or IPv6 addresses in the same /64.
pub fn same_host(a: IpAddr, b: IpAddr) -> bool {
    ip_key(a) == ip_key(b)
}

/// A global unicast IPv6 address (2000::/3) with a port: all a genuine client
/// reports, and nothing that points into a LAN or at a multicast group.
pub fn usable_v6(addr: SocketAddr) -> bool {
    match addr {
        SocketAddr::V6(v6) => {
            v6.port() != 0
                && v6.ip().to_ipv4_mapped().is_none()
                && (v6.ip().segments()[0] & 0xe000) == 0x2000
        }
        SocketAddr::V4(_) => false,
    }
}

/// Whether a client version string is 1.5.0 or newer.
pub fn is_1_5(version: &str) -> bool {
    hbb_common::get_version_number(version) >= hbb_common::get_version_number("1.5.0")
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Token buckets per key, at most `MAX_LIMITER_ENTRIES` keys.
pub struct Limiter {
    burst: f64,
    rate: f64,
    buckets: HashMap<IpAddr, Bucket>,
}

impl Limiter {
    pub fn new(burst: f64, rate: f64) -> Self {
        Self {
            burst,
            rate,
            buckets: HashMap::new(),
        }
    }

    fn refill(&self, b: &mut Bucket, now: Instant) {
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * self.rate).min(self.burst);
        b.at = now;
    }

    /// Take one token for `key`, or `false` when it has none left.
    pub fn take(&mut self, key: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= MAX_LIMITER_ENTRIES {
            // Buckets that refilled completely say nothing a new one would not.
            let full = self.burst / self.rate;
            self.buckets
                .retain(|_, b| now.duration_since(b.at).as_secs_f64() < full);
            if self.buckets.len() >= MAX_LIMITER_ENTRIES {
                return false;
            }
        }
        let burst = self.burst;
        let mut b = *self.buckets.entry(key).or_insert(Bucket { tokens: burst, at: now });
        self.refill(&mut b, now);
        let ok = b.tokens >= 1.;
        if ok {
            b.tokens -= 1.;
        }
        self.buckets.insert(key, b);
        ok
    }
}

/// One global bucket.
struct Global {
    tokens: f64,
    at: Instant,
}

/// A controller connection that was granted UDP punching or had its IPv6
/// address sent to the device.
#[derive(Clone, Debug)]
pub struct Route {
    /// The device asked for.
    pub target: String,
    /// The address the device registered from, when the request was made.
    pub target_ip: IpAddr,
    /// `udp_port` went to the device, and its UDP reply has not come yet.
    pub udp: bool,
    /// The controller's IPv6 address went to the device.
    pub v6: bool,
    pub created: Instant,
}

pub struct Punches {
    routes: HashMap<SocketAddr, Route>,
    nat_test: Limiter,
    nat_test_global: Global,
    v6_by_controller: Limiter,
    v6_by_target: Limiter,
    old_clients: HashMap<String, Instant>,
}

impl Default for Punches {
    fn default() -> Self {
        Self {
            routes: HashMap::new(),
            nat_test: Limiter::new(NAT_TEST_BURST, NAT_TEST_RATE),
            nat_test_global: Global {
                tokens: NAT_TEST_GLOBAL_RATE * 2.,
                at: Instant::now(),
            },
            v6_by_controller: Limiter::new(V6_BURST, V6_RATE),
            v6_by_target: Limiter::new(V6_BURST, V6_RATE),
            old_clients: HashMap::new(),
        }
    }
}

impl Punches {
    /// Whether a UDP `TestNatRequest` from `src` may be answered.
    pub fn nat_test_allowed(&mut self, src: IpAddr, now: Instant) -> bool {
        let g = &mut self.nat_test_global;
        g.tokens = (g.tokens + now.duration_since(g.at).as_secs_f64() * NAT_TEST_GLOBAL_RATE)
            .min(NAT_TEST_GLOBAL_RATE * 2.);
        g.at = now;
        if g.tokens < 1. {
            return false;
        }
        if !self.nat_test.take(ip_key(src), now) {
            return false;
        }
        self.nat_test_global.tokens -= 1.;
        true
    }

    /// Whether `controller` may hand the IPv6 address `target` to a device.
    /// A target in the controller's own /64 counts only against the
    /// controller: the probes go to its own network.
    pub fn v6_allowed(&mut self, controller: IpAddr, target: SocketAddr, now: Instant) -> bool {
        if !self.v6_by_controller.take(ip_key(controller), now) {
            return false;
        }
        same_host(controller, target.ip()) || self.v6_by_target.take(ip_key(target.ip()), now)
    }

    /// Whether the device's own IPv6 address may go back to the controller.
    pub fn v6_back_allowed(&mut self, target: SocketAddr, now: Instant) -> bool {
        self.v6_by_target.take(ip_key(target.ip()), now)
    }

    /// Open (or replace) the route of controller connection `key`. `false`
    /// when the controller IP already holds `MAX_ROUTES_PER_IP`, or the table
    /// is full of live routes.
    pub fn open(&mut self, key: SocketAddr, route: Route) -> bool {
        let now = route.created;
        self.routes.retain(|_, r| now.duration_since(r.created) < ROUTE_TTL);
        if !self.routes.contains_key(&key) {
            let ip = ip_key(key.ip());
            let mine = self.routes.keys().filter(|k| ip_key(k.ip()) == ip).count();
            if mine >= MAX_ROUTES_PER_IP || self.routes.len() >= MAX_ROUTES {
                return false;
            }
        }
        self.routes.insert(key, route);
        true
    }

    /// The live route of controller connection `key`.
    pub fn get(&self, key: SocketAddr, now: Instant) -> Option<&Route> {
        self.routes
            .get(&key)
            .filter(|r| now.duration_since(r.created) < ROUTE_TTL)
    }

    /// Claim the UDP answer of route `key` for a `PunchHoleSent` from device
    /// `id` arriving from `src`. Only the first matching one counts; one that
    /// does not match leaves the route as it was, so a forged datagram cannot
    /// use up the answer the device's needs.
    pub fn claim_udp(&mut self, key: SocketAddr, id: &str, src: IpAddr, now: Instant) -> Option<Route> {
        let route = self.routes.get_mut(&key)?;
        if !route.udp
            || route.target != id
            || !same_host(route.target_ip, src)
            || now.duration_since(route.created) >= ROUTE_TTL
        {
            return None;
        }
        route.udp = false;
        Some(route.clone())
    }

    /// The controller's connection closed.
    pub fn close(&mut self, key: SocketAddr) {
        self.routes.remove(&key);
    }

    /// A device answered with this version, from its registered host.
    pub fn note_version(&mut self, id: &str, version: &str, now: Instant) {
        if version.is_empty() || is_1_5(version) {
            self.old_clients.remove(id);
            return;
        }
        if !self.old_clients.contains_key(id) && self.old_clients.len() >= MAX_OLD_CLIENTS {
            self.old_clients
                .retain(|_, at| now.duration_since(*at) < OLD_CLIENT_TTL);
            if self.old_clients.len() >= MAX_OLD_CLIENTS {
                return;
            }
        }
        self.old_clients.insert(id.to_owned(), now);
    }

    /// Whether device `id` is known to run a client before 1.5.
    pub fn is_old_client(&self, id: &str, now: Instant) -> bool {
        self.old_clients
            .get(id)
            .map_or(false, |at| now.duration_since(*at) < OLD_CLIENT_TTL)
    }

    #[cfg(test)]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn route(target: &str, ip: &str, udp: bool, v6: bool, created: Instant) -> Route {
        Route {
            target: target.to_owned(),
            target_ip: ip.parse().unwrap(),
            udp,
            v6,
            created,
        }
    }

    #[test]
    fn addresses() {
        assert!(usable_v6(a("[2001:db8::1]:5")));
        for bad in ["[2001:db8::1]:0", "[fe80::1]:5", "[fd00::1]:5", "[ff02::1]:5", "[::1]:5", "[::ffff:1.2.3.4]:5", "1.2.3.4:5"] {
            assert!(!usable_v6(a(bad)), "{bad}");
        }
        assert!(same_host("2001:db8:1:2::5".parse().unwrap(), "2001:db8:1:2::9".parse().unwrap()));
        assert!(!same_host("2001:db8:1:2::5".parse().unwrap(), "2001:db8:1:3::5".parse().unwrap()));
        assert!(same_host("::ffff:192.0.2.1".parse().unwrap(), "192.0.2.1".parse().unwrap()));
        assert!(!same_host("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()));
        assert!(is_1_5("1.5.0") && is_1_5("1.5.2") && is_1_5("1.6.0"));
        assert!(!is_1_5("1.4.9") && !is_1_5(""));
    }

    #[test]
    fn nat_test_answers_are_limited_per_source_and_refill() {
        let mut p = Punches::default();
        let now = Instant::now();
        let src: IpAddr = "192.0.2.7".parse().unwrap();
        let answered = (0..100).filter(|_| p.nat_test_allowed(src, now)).count();
        assert_eq!(answered, NAT_TEST_BURST as usize);
        // Another host is not held up by that one.
        assert!(p.nat_test_allowed("192.0.2.8".parse().unwrap(), now));
        // A whole IPv6 /64 is one source.
        let n = (0..100u16)
            .filter(|i| p.nat_test_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, *i)), now))
            .count();
        assert_eq!(n, NAT_TEST_BURST as usize);
        // One second later, 30 more.
        let later = now + Duration::from_secs(1);
        assert_eq!((0..100).filter(|_| p.nat_test_allowed(src, later)).count(), NAT_TEST_RATE as usize);
    }

    #[test]
    fn the_global_nat_test_budget_holds() {
        let mut p = Punches::default();
        let now = Instant::now();
        let answered = (0..20_000u32)
            .filter(|i| p.nat_test_allowed(IpAddr::V4((0x0a00_0000 + i).into()), now))
            .count();
        assert_eq!(answered, (NAT_TEST_GLOBAL_RATE * 2.) as usize);
    }

    #[test]
    fn limiter_tables_are_bounded() {
        let mut l = Limiter::new(2., 1.);
        let now = Instant::now();
        for i in 0..MAX_LIMITER_ENTRIES as u32 {
            assert!(l.take(IpAddr::V4(i.into()), now));
        }
        assert!(!l.take("203.0.113.1".parse().unwrap(), now), "full: a new source is refused");
        assert!(l.take(IpAddr::V4(5u32.into()), now), "known sources still work");
        // Once the old buckets have refilled they make room.
        assert!(l.take("203.0.113.1".parse().unwrap(), now + Duration::from_secs(3)));
    }

    #[test]
    fn v6_forwards_are_limited_per_controller_and_per_target() {
        let mut p = Punches::default();
        let now = Instant::now();
        let target = a("[2001:db8:9::1]:5000");
        let ok = (0..100u32)
            .filter(|i| p.v6_allowed(IpAddr::V4((0xc000_0200 + i).into()), target, now))
            .count();
        assert_eq!(ok, V6_BURST as usize, "one target /64, many controllers");
        let ctl: IpAddr = "198.51.100.1".parse().unwrap();
        let ok = (0..100u16)
            .filter(|i| p.v6_allowed(ctl, SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, *i, 0, 0, 0, 0, 1)), 5), now))
            .count();
        assert_eq!(ok, V6_BURST as usize, "one controller, many targets");
        // Its own /64 counts only against the controller.
        let mut p = Punches::default();
        let me: IpAddr = "2001:db8:7::5".parse().unwrap();
        let mine = a("[2001:db8:7::6]:5");
        assert!((0..60).all(|_| p.v6_allowed(me, mine, now)));
        assert!(p.v6_back_allowed(mine, now));
    }

    #[test]
    fn routes_match_only_their_device_once() {
        let mut p = Punches::default();
        let now = Instant::now();
        let ctl = a("198.51.100.1:40000");
        assert!(p.open(ctl, route("123456789", "192.0.2.5", true, false, now)));
        // Wrong device, wrong host, then a forged one: the route stays.
        assert!(p.claim_udp(ctl, "999999999", "192.0.2.5".parse().unwrap(), now).is_none());
        assert!(p.claim_udp(ctl, "123456789", "192.0.2.6".parse().unwrap(), now).is_none());
        assert!(p.claim_udp(ctl, "123456789", "::ffff:192.0.2.5".parse().unwrap(), now).is_some());
        // The device's second and third copies change nothing.
        assert!(p.claim_udp(ctl, "123456789", "192.0.2.5".parse().unwrap(), now).is_none());
        // Expired.
        assert!(p.open(ctl, route("123456789", "192.0.2.5", true, false, now)));
        assert!(p.claim_udp(ctl, "123456789", "192.0.2.5".parse().unwrap(), now + ROUTE_TTL).is_none());
        p.close(ctl);
        assert!(p.get(ctl, now).is_none());
    }

    #[test]
    fn routes_are_bounded_per_controller_ip() {
        let mut p = Punches::default();
        let now = Instant::now();
        for port in 0..MAX_ROUTES_PER_IP as u16 {
            assert!(p.open(SocketAddr::new("198.51.100.1".parse().unwrap(), 1000 + port), route("1", "192.0.2.5", true, false, now)));
        }
        assert!(!p.open(a("198.51.100.1:9999"), route("1", "192.0.2.5", true, false, now)));
        assert!(p.open(a("198.51.100.2:9999"), route("1", "192.0.2.5", true, false, now)));
        // Expired routes make room.
        assert!(p.open(a("198.51.100.1:9999"), route("1", "192.0.2.5", true, false, now + ROUTE_TTL)));
        assert_eq!(p.route_count(), 1);
    }

    #[test]
    fn older_clients_are_remembered_and_forgotten() {
        let mut p = Punches::default();
        let now = Instant::now();
        p.note_version("123456789", "1.4.9", now);
        assert!(p.is_old_client("123456789", now));
        p.note_version("123456789", "1.5.0", now);
        assert!(!p.is_old_client("123456789", now));
        p.note_version("123456789", "1.4.9", now);
        assert!(!p.is_old_client("123456789", now + OLD_CLIENT_TTL));
    }
}
