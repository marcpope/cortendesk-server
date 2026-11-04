# Changes from rustdesk-server

This file is the statement of modifications required by section 5(a) of the
GNU Affero General Public License. It lists every change made to the original
work, with the date it was made.

**Base:** [rustdesk-server](https://github.com/rustdesk/rustdesk-server) release
`1.1.17`, up to commit `a7736be` of 2026-08-07, merged in 1.1.1. Forked from
release `1.1.16`, commit `73523b3`, published 2026-07-21. Copyright of the
original work remains with its authors; see LICENSE and NOTICE.

Versions below are CortenDesk Server versions. They are numbered independently
of upstream so the two are never mistaken for each other.

---

## 1.3.1 (unreleased)

### hbbr: legs that arrive together are paired (2026-11-04)

Issue #3. Reported upstream with a repro by @wb113, rustdesk-server issue 708;
based on a fix proposed upstream by @jahvari, rustdesk-server PR 721.

- The second leg of a session is looked up and the first is stored under one
  lock. Before, when both arrived at the same moment, each could miss the
  other, the second replaced the first, and the session failed.
- A waiting leg that expires after 30 seconds removes only itself. Before, it
  removed whatever waited under its uuid, which could be a newer leg.
- Tests: in `tests/relay_websocket.rs`, 64 sessions whose two legs arrive
  together; a unit test for the expiry in `src/relay_server.rs`.

### hbbr: relay writes time out (2026-11-04)

Issue #2. Based on a fix proposed upstream by @jahvari, rustdesk-server PR 723.

- A write to either side of a relayed session that takes over 30 seconds ends
  the session. Before, when one side stopped reading (a frozen app, or a dead
  network that never sends a reset), the write waited forever, the 30-second
  idle check never ran, and the session and its relay report never closed.
- Unit test in `src/relay_server.rs`.

## 1.3.0 (2026-11-03)

### Connection paths for the console's connection log (2026-11-03)

A device's connection audit does not say how the session got through. The
console now shows it per connection (CortenDesk issue #130).

- `hbbs` puts a tag in `controlled_context.conn_audit_ref` of every
  `PunchHole` (`cd1/punch`, or `cd1/punch-webrtc` with a WebRTC offer),
  `FetchLocalAddr` (`cd1/lan`) and forwarded `RequestRelay` (`cd1/relay`).
  RustDesk 1.5 devices echo it unchanged in their connection audit.
- `hbbr` keeps the first side's request while it waits for the second, so the
  pair knows the device ID and connection type from the controller's request,
  whichever side arrives first.
- New `src/relay_report.rs`: `hbbr` reports each pair to the console at
  `POST /api/server/relay-sessions` when it forms and again when it closes,
  with both peers' addresses and the bytes it carried. Reports are batched
  every 5 seconds, up to 5000 kept while the console is unreachable. It runs
  only with `CORTENDESK_CONSOLE_URL` and `CORTENDESK_SERVER_SECRET` set, the
  same two settings `hbbs` uses.
- Tests: `tests/relay_report.rs` against a real `hbbr` and a stand-in
  console; the tags are checked in `tests/access_policy.rs` and
  `tests/webrtc_signalling.rs`.

### WebSocket and TCP registration for desktop clients (2026-11-03)

Based on pull request #1 by vk2amv, which credits ideas from SctgDesk Server,
lejianwen/rustdesk-server and BetterDesk (all AGPL-3.0; no code taken from
them). Ported onto 1.3.0 with the fixes below.

- `hbbs` accepts `RegisterPk` over TCP and WebSocket. Upstream answers
  `NOT_SUPPORT`, so desktop clients in WebSocket mode, or with a proxy or
  `disable-udp`, never come online. The connection stays open as the device's
  registration: `keep_alive` 20 seconds, an empty heartbeat every 10, dropped
  after 30 silent. The newest registration of an ID replaces the old one; UDP
  presence is tracked apart from it.
- `PunchHole`, `RequestRelay` and ICE candidates for a device registered this
  way go over its connection, with the `cd1/` tags. Sessions to or from a
  WebSocket client are relayed. `OnlineRequest` is answered on WebSocket.
- Each connection has one writer and a queue of 64 messages; a full queue or a
  write over 5 seconds closes it. A connection gets one reply through
  `tcp_punch` per punch hole or relay request it sent, at most 8 owed;
  anything else addressed to it by IP and port is dropped.
- Registrations of the same ID are serialised by a lock for that ID. The UDP
  loop never waits on it: a UDP `RegisterPk` that finds it taken gets
  `TOO_FREQUENT` and the client retries. A failed database write returns
  `SERVER_ERROR` and claims nothing.
- New `TRUSTED_PROXIES` / `--trusted-proxies` on `hbbs` and `hbbr`:
  comma-separated CIDRs of reverse proxies. On the WebSocket ports a
  connection from one of them is identified by `X-Forwarded-For`, read from
  the right: the first address that is not a listed proxy is the client.
  Entries a client wrote to the left are never used. Default empty: no proxy
  is trusted. `X-Real-IP` is no longer read. Before this, both servers took
  `X-Real-IP` or the first `X-Forwarded-For` entry from anyone (upstream issue
  #634).
- That one client address is used for registration, the per-IP rate limit, the
  IP/key mismatch check, the device policy's address match and LAN address
  reports. So incoming-only is now enforced for signed-out WebSocket clients
  behind a proxy; before, they all looked like the proxy. Stream heartbeats
  keep the policy's address match fresh, as UDP `RegisterPeer` does.
- Fixed in the port: the PR keyed TCP connections by plain IPv4 while UDP
  peers on a dual-stack socket stay IPv4-mapped, so same-NAT pairs no longer
  got `FetchLocalAddr` (`cd1/lan`). Both sides are now compared normalised.
- `hbbr`: WebSocket handshake times out after 5 seconds, and the block list is
  checked against the client address on WebSocket too.
- A UDP `RegisterPk` without uuid or key is still dropped without a reply.
- README: "WebSocket desktop clients"; `docs/environment-variables.md`:
  `TRUSTED_PROXIES`. NOTICE names the new files.
- New `src/stream_connection.rs`. Tests: `tests/stream_registration.rs`
  (registration, heartbeats, reconnects, shared addresses, persistence
  failure, relay framing for every native/WebSocket pair, the `cd1/punch` and
  `cd1/relay` tags, one reply per request), and in `tests/access_policy.rs`
  incoming-only over WebSocket behind a proxy.

## 1.2.0 (2026-11-01)

### WebRTC signalling for RustDesk 1.5 clients (2026-11-01)

RustDesk 1.5 can connect over WebRTC when the controlling client has
`enable-webrtc` on. The client puts an SDP offer in its punch hole request and
both sides then exchange ICE candidates through `hbbs`. Upstream `hbbs` drops
all of it, so those clients fall back to their other transports.

- `libs/hbb_common` moved to `229b904`, the commit RustDesk 1.5.0 builds
  with, for the new message fields.
- `hbbs` passes the offer to the device in `PunchHole`, and the device's
  answer back in `PunchHoleResponse` or `RelayResponse`.
- `hbbs` forwards `IceCandidate` messages: from the controller to the device
  it offered to, by device ID, and from the device to the controller, by the
  controller's address. The controller's connection stays open for the
  exchange instead of closing after the first reply.
- New `src/webrtc_signal.rs` keeps one route per offering connection. Only a
  connection that sent an offer the access policy allowed can send candidates,
  only to that device, at most 64 each way, for at most 60 seconds.
- Offers on a connection that is not encrypted are dropped, since offers,
  answers and candidates carry both machines' addresses. RustDesk 1.5 only
  offers on an encrypted connection.
- A route holds at most 64 messages towards the controller, answers and
  replies included, and one IP can hold at most 64 routes at once. Offers and
  answers are capped at 16 KB.
- Writes to a client connection time out after 5 seconds, so a client that
  stops reading cannot hold replies queued behind it. This also covers the
  ordinary punch-hole reply, which upstream sends without a timeout. A route
  whose connection fails a write is dropped.
- A WebSocket connection whose client address comes from `X-Real-IP` or
  `X-Forwarded-For` is keyed by that IP and its own connection port, not port
  0. Upstream gives every such client behind one IP the same key, so a reply
  could go to the wrong one; routes keep connections open long enough to make
  that likely.
- Dependencies brought in by the newer `hbb_common` updated: rustls 0.23.46,
  rustls-webpki 0.103.16, webpki-roots and webpki-root-certs 1.0.11, zstd-sys
  2.1.2. Advisories that no compatible update fixes are listed, with the
  reason they do not reach `hbbs` or `hbbr`, in `.cargo/audit.toml`.
- Known limitation: candidates sent towards the controller are not checked
  against the device's own address. A sender would need the controller's
  address and source port within the route's 60 seconds.
- New test `tests/webrtc_signalling.rs`.

## 1.1.1 (2026-10-08)

### Merged upstream rustdesk-server 1.1.17

Upstream changes from `73523b3` to `a7736be`, taken as they are:

- `hbbs` ignores `PunchHoleSent` and `LocalAddr` arriving over UDP. Both made
  the server send a reply to an address named inside the packet, which a
  spoofed sender could aim at a third party (reflection/amplification).
  Clients send these over TCP, which is unchanged.
- A comment on the WebSocket listeners of `hbbs` and `hbbr` warning that
  `X-Real-IP` / `X-Forwarded-For` are trusted as sent, so the WebSocket ports
  belong behind a reverse proxy (upstream issue #634). Upstream changed no
  code for this. See below for the one place this fork stopped trusting them.
- `-b` / `--bind` / `BIND` on `hbbs` and `hbbr` to listen on one local address.
  When that address does not cover `127.0.0.1`, the loopback admin port gets
  its own listener on `127.0.0.1`.
- Option names are matched ignoring case and `-` versus `_`, in flags, `.env`,
  `--config` and the environment.
- `hbbs --help` marks `-s`, `-R`, `-u` and `--mask` as deprecated. They still
  work.
- `docs/environment-variables.md`, a reference for every option.
- protobuf 3.7.2, with a regression test for nested-message recursion
  (`tests/protobuf_recursion.rs`).
- `libs/hbb_common` moved to upstream's pin, `69cea8d`.

Not carried: upstream's changes to files this fork does not ship
(`.github/workflows/build.yaml`, `debian/changelog`, `ui/setup.nsi`), and the
contributor instruction files `AGENTS.md` and its alias.

### Changes made during the merge

- The daily update check stays removed. Upstream's `main.rs` still called it;
  that call is dropped, and imports it alone used are gone from
  `src/common.rs`.
- `src/policy.rs` reads `CORTENDESK_CONSOLE_URL`, `CORTENDESK_SERVER_SECRET`
  and `CORTENDESK_POLICY_INTERVAL` through the same lookup as every other
  option, so they now also work from `.env` and `--config`. Before, only the
  process environment worked.
- `docs/environment-variables.md` adapted to this fork: version numbers, the
  policy variables, the `policy` admin command, `cortendesk-utils`, and this
  project's Docker image (working directory `/root`, none of the s6 image's
  variables) in place of upstream's images.
- LAN address reports to the console take the sender from the TCP peer
  address (`src/rendezvous_server.rs`). Before, they used the address `hbbs`
  works with internally, which on the WebSocket port comes from `X-Real-IP` /
  `X-Forwarded-For`. A client reaching that port directly could forge the
  header and pass the check that the answer comes from the address the device
  registered from. The punch hole and relay policy checks already used the TCP
  peer. New test in `tests/access_policy.rs`.
- OpenSSL is built from source (`openssl` crate, `vendored` feature) on Linux.
  The new `hbb_common` links native-tls, which is OpenSSL on Linux, for both
  the binaries and the build script, and the static musl builds have no
  system OpenSSL to link against.

### Dependency security updates

- `tungstenite` and `tokio-tungstenite` 0.17 to 0.26 (RUSTSEC-2023-0065: a
  crafted WebSocket handshake could make the server spend unbounded CPU, with
  no authentication, on the WebSocket ports). Two call sites in
  `src/relay_server.rs` and `src/rendezvous_server.rs` adapted to the newer
  message type. New test `tests/relay_websocket.rs` runs a real `hbbr` and
  checks WebSocket-to-WebSocket and WebSocket-to-TCP relaying, and that the
  relay key is enforced on WebSocket.
- `cargo update` within the existing version requirements, which retires the
  advisories for `bytes`, `h2`, `axum-core`, `crossbeam-epoch`, `openssl`,
  `rustls`, `rustls-webpki`, `webpki` and `remove_dir_all`.
- Security scanning in CI: `cargo audit` (accepted advisories listed with
  reasons in `.cargo/audit.toml`), gitleaks, and CodeQL for Rust.
- README: a short Configuration section pointing at that document.
- `docs/environment-variables.md`: a note that the WebSocket ports trust
  `X-Real-IP` / `X-Forwarded-For` and belong behind a reverse proxy.
- NOTICE: `tests/protobuf_recursion.rs` comes from upstream, so the list of
  files this project added names its two test files instead of all of
  `tests/`.

### Version

Package version `1.1.1`.

---

## 1.1.0 (2026-09-29)

### Device access policy from a CortenDesk console (`src/policy.rs`, `src/rendezvous_server.rs`)

New. `hbbs` can take its access policy from a CortenDesk console, so a server
can refuse devices the console has not approved and devices marked
incoming-only. Off unless `CORTENDESK_CONSOLE_URL` and
`CORTENDESK_SERVER_SECRET` are both set; without them `hbbs` behaves exactly
as 1.0.0.

- Every `CORTENDESK_POLICY_INTERVAL` seconds (default 5) `hbbs` fetches
  `GET <console>/api/server/policy` with the secret as a bearer token: the mode,
  the approved devices, the incoming-only devices, and SHA-256 hashes of console
  access tokens with the device each was issued to. Unchanged policy answers
  304. Checks run against the copy in memory; no request waits on HTTP.
- The last good policy is kept when the console is unreachable, and saved to
  `policy_snapshot.json` in the working directory so a restart applies it
  before the console answers. With no policy at all (first start, console
  down) every device is allowed and the log says so.
- A punch hole request or relay request whose sender may not start sessions
  is refused with a message the client shows (`other_failure` /
  `refuse_reason`). In approved-only mode a request for a device that is not
  approved is refused the same way. Registration is unaffected, so unapproved
  devices still come online and reach the console.
- The request does not name its sender. `hbbs` identifies it by, in order: a
  ticket signed with the shared secret (the console's own web client), the
  console access token signed-in clients send, or the TCP peer address matched
  against devices registered from that address in the last 30 seconds, not
  counting the target. Forwarded-for headers are not trusted for this. In
  approved-only mode the address match is used only when the console's policy
  sets `ip_match`.
- When a device answers a local address request, `hbbs` records its LAN
  address and posts it to `<console>/api/server/local-addrs`, batched, once per
  address per device every 10 minutes at most, and only when the answer comes
  from the address that device registered from.
- New admin command `policy` (`pol`) on the loopback admin port prints the
  current policy state.
- `hbbr` is unchanged.

Added `tests/access_policy.rs` (end-to-end against a real `hbbs` process and a
fake console) and unit tests in `src/policy.rs`.

### Version

Package version `1.1.0`.

---

## 1.0.0 — 2026-08-10

### Encrypted signalling in `hbbs` (`src/rendezvous_server.rs`)

Implements the server half of the signalling key exchange, which the original
work does not have. Without it, RustDesk clients 1.4.1 and newer cannot connect
at all while signed in to an API server: the client waits for a key exchange
that never arrives and fails with "Failed to secure tcp: deadline has elapsed".

- On each plain-TCP connection, `hbbs` now sends the client a throwaway
  Curve25519 public key signed with the server's Ed25519 key, before reading
  anything. Skipped when the server has no key pair, since an unsigned offer
  proves nothing.
- When the client answers with its own public key and a sealed symmetric key,
  the connection is encrypted in both directions from that point on.
- A connection whose first frame is not a key exchange continues in plain text,
  so clients that do not encrypt signalling are unaffected. A key exchange that
  is malformed or cannot be opened closes the connection rather than falling
  back, so the encryption cannot be stripped by an intermediary.
- WebSocket connections are left alone: clients skip this exchange there.
- `hbbr` is unchanged. Clients never run this exchange against the relay.

Added `tests/signalling_handshake.rs` (end-to-end against a real `hbbs` process,
covering both a signed-in and a signed-out client) and unit tests in
`src/rendezvous_server.rs`.

### Removed the daily update check (`src/common.rs`, `src/main.rs`)

`hbbs` polled RustDesk's release feed once a day and logged when a newer
rustdesk-server existed. It compared their version numbers against ours, so a
current build reported itself as out of date, and it made a daily outbound
request to a third party that a self-hosted server has no reason to make.

### Naming

- Product name, author string and `--help` descriptions changed from RustDesk's
  to this project's. The RustDesk name is retained only where it factually
  describes what the software is compatible with. The binaries `hbbs` and `hbbr`
  keep their names, since every existing deployment, flag and document depends
  on them.
- `rustdesk-utils` renamed to `cortendesk-utils`.
- Package version reset to `1.0.0` and versioned independently of upstream.

### Removed

Not carried into this fork, and not published in any form: `debian/` packaging,
the `ui/` Windows installer and service UI, `rcd/` service scripts, the s6
Docker image under `docker/`, `docker-classic/`, `kubernetes/`, and upstream's
GitHub Actions workflows and issue templates. Replaced by a single Docker image
and static Linux binaries, built by `.github/workflows/release.yml`.
