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

### hbbs: `release-id` admin command (2026-11-04)

Issue #19. Requested upstream by @shahidullahr, rustdesk-server issue 483.

- `release-id <id>` / `rid <id>` on the loopback admin console deletes the
  device from the database and from memory and closes its WebSocket or TCP
  registration, so another machine can register the ID. Before, a reinstalled
  machine could not take back its custom ID: the old entry kept it, and the
  only fix was editing `db_v2.sqlite3` with `hbbs` stopped.
- It waits for any registration of that ID in progress, under the same per-ID
  lock.
- One line back: `OK <id>`, `OK <id> online` (it was online and may register
  again at once if that machine still runs), `NOT_FOUND <id>` or
  `ERROR <reason>`. For the CortenDesk console's "Release ID" button.
- README (Configuration) and `docs/environment-variables.md` (Runtime console).
- Test in `tests/admin_console.rs`: a live registration released and taken by
  another machine, then a database-only one after a restart.

### hbbs: one failed UDP reply no longer rebuilds the UDP socket (2026-11-04)

Issue #9. Based on a fix proposed upstream by @jahvari, rustdesk-server
PR 738, done in this tree because that PR changes `hbb_common`.

- A UDP reply that fails is logged at debug level and dropped. Before, it
  rebuilt the UDP socket, and every client's packets were lost meanwhile.
  Under load (`ENOBUFS`) or with odd source addresses this could repeat.
- Replies are written to the socket directly. `hbb_common`'s
  `FramedSocket::send` goes through tokio-util's `UdpFramed`, which keeps a
  datagram whose send failed and sends it again before every later one, so
  after one failure every reply failed until the socket was rebuilt. That is
  why the rebuild was there.
- Datagrams from port 0 or from a broadcast, multicast or unspecified address
  are ignored: there is nothing to answer.
- A failed receive still rebuilds the socket, as before.
- Unit tests in `src/rendezvous_server.rs`.

### README: reverse proxy advice for the WebSocket ports (2026-11-04)

- "Running it" told operators to put the WebSocket ports behind a proxy that
  sets `X-Real-IP`. Since 1.3.0 that header is never read; the client address
  comes from `X-Forwarded-For`, and only from a proxy listed in
  `TRUSTED_PROXIES`. The paragraph now says so.

### Release source tarball with submodules (2026-11-04)

Issue #16. Reported upstream by @SecurityCze, rustdesk-server issue 701.

- `.github/workflows/release.yml` has a new `source` job that, for a published
  release, attaches `cortendesk-server-<tag>-src.tar.gz`: the tagged tree and
  the `libs/hbb_common` submodule, under one top directory. GitHub's own
  "Source code" archives leave the submodule out and cannot be built. The
  other jobs are unchanged.
- README: the tarball, under Running it.

### Build script without hbb_common (2026-11-04)

Issue #15. Based on a change proposed upstream by @luminoso, rustdesk-server
PR 707.

- `build.rs` writes `src/version.rs` from `CARGO_PKG_VERSION` itself, and only
  when it changed. Before, it called `hbb_common::gen_version`, which made
  `hbb_common`, and with it vendored OpenSSL, a build dependency: compiled a
  second time for the build host, which slowed builds and complicated
  cross-compiling.
- `src/version.rs` no longer has `BUILD_DATE`, which nothing used.
- `hbb_common` and `openssl` are no longer build dependencies.

### Unused dependencies removed (2026-11-04)

Issue #13. Based on a change proposed upstream by @jahvari, rustdesk-server
PR 729.

- Removed, as nothing in `src/` or `tests/` uses them: `bcrypt`,
  `jsonwebtoken`, `tower-http`, `headers`, `http`, `regex`, `flate2`,
  `whoami`, `machine-uid`, `mac_address`, `ping`, and `minreq`, which only the
  removed update check used. `Cargo.lock` loses those and what only they
  pulled in; nothing else changed version.
- `axum` moved to a test-only dependency: only the stand-in console in
  `tests/access_policy.rs` uses it.
- `ring` 0.16 stays: `sqlx` 0.6 pulls it in through `rustls` 0.20.

### hbbs: per-IP registration limits are settings (2026-11-04)

Issue #12. Based on a change proposed upstream by @devhem, rustdesk-server
PR 742, with the same setting names.

- `MAX_NEW_IDS_PER_IP` / `--max-new-ids-per-ip` (default 300): distinct IDs
  one client IP may register in 24 hours. `MAX_REGISTER_BURST_PER_IP` /
  `--max-register-burst-per-ip` (default 30): registrations from one IP
  without a 60-second pause. Both were fixed in the code. A company or MSP
  with many machines behind one NAT hit the first, and new machines showed
  "ID does not exist". Read from the environment, `.env`, `--config` or the
  flag; a value that is not a positive whole number is logged and the
  default used. Both are logged at start.
- The limits now count exactly. Before, the first registration from an IP
  was not counted towards either, and each check let one more through, so
  32 registrations in a row and 302 IDs were allowed.
- They cover every registration path: `RegisterPk` over UDP, TCP and
  WebSocket.
- README (Configuration) and `docs/environment-variables.md`.
- Test in `tests/stream_registration.rs`, one limit set by flag and one by
  environment.

### hbbs: the UDP self-test survives failed sends (2026-11-04)

Issue #11. Reported upstream by @littletow, rustdesk-server issue 444.

- A failed send in the self-test (`TEST_HBBS`), for example `EPERM` from a
  firewall, is logged once and retried every second. Before, one failed send
  ended the process with `exit(1)`, so `hbbs` stopped after running for a
  while and stayed down unless something restarted it.
- A self-test that cannot start, on IPv6 and then IPv4, is logged and dropped;
  `hbbs` keeps running. Before, that also exited.
- Kept from upstream: once `hbbs` has answered the self-test, 12 seconds of
  sent requests without an answer still exit the process so a supervisor
  restarts it. Failed sends do not count towards those 12 seconds.
- Unit test in `src/rendezvous_server.rs`.

### Admin console replies arrive whole (2026-11-04)

Issue #8. Based on a fix proposed upstream by @jahvari, rustdesk-server PR 717.

- The loopback admin consoles of `hbbs` and `hbbr` write the whole reply.
  Before, they wrote once and closed, so a reply larger than the socket could
  take at once, such as a long block list, arrived cut short.
- Test in `tests/admin_console.rs`: a 3 MB block list from `hbbr`, read
  slowly.

### Message size limits before sign-in and pairing (2026-11-04)

Issue #7. Based on the message size limits proposed upstream by @jahvari,
rustdesk-server PR 726. That PR's cap on connections is not taken: every
device registered over WebSocket or TCP holds a connection.

- `hbbs`: signalling messages are at most 1 MiB, on TCP (frame length, checked
  on the frame header) and on WebSocket (`max_message_size` and
  `max_frame_size`). A larger one closes the connection. Before, a TCP frame
  could announce up to 1 GiB and a WebSocket message 64 MiB.
- `hbbr`: before a connection is paired it may send at most 64 KB: on TCP a
  frame longer than that, on WebSocket more than that many bytes in all,
  handshake included, closes it. Once paired, the limits are what they were.
  tungstenite cannot change a WebSocket's message limits once it is open, so
  on WebSocket the limit is on bytes read from the socket.
- Tests: in `tests/stream_registration.rs`, an online request of 40000 IDs
  still answered and oversized TCP and WebSocket frames refused; in
  `tests/relay_websocket.rs`, oversized frames before pairing refused and
  2 MB messages carried after it, WebSocket to WebSocket and TCP to
  WebSocket.

### Key files: unreadable private key stops the server, stale `.pub` rewritten (2026-11-04)

Issue #6. Reported upstream by @layer6org, rustdesk-server issue 678. Ported
from upstream rustdesk-server commit 873230e, which came after this fork's base.

- An `id_ed25519` that exists but cannot be opened or read, or does not hold a
  valid key, stops `hbbs` (and `hbbr` with `-k -` or `-k _`) with an error.
  Before, an unreadable one was treated as missing: a new random
  `id_ed25519.pub` was written, the private key could not be, and clients
  configured with the new `.pub` got "Key mismatch". A malformed key already
  stopped the server; it now does so with an error instead of `exit(1)`.
- A new private key is created with mode `0600`, never over an existing file.
  An existing one with group or other permission bits is set to `0600`;
  `0400` is kept.
- A missing `id_ed25519.pub` is written from the private key, mode `0644`,
  through a temporary file so it is never seen half written. One that does
  not match the private key is logged as a warning and rewritten from it: the
  server signs with the private key either way, and refusing to start would
  turn a stale `.pub` into a restart loop on upgrade. Upstream refuses here.
  Before, a stale `.pub` was left as it was, without a word.
- Symlinked key paths are followed, at most 40 links.
- `tempfile` moved from a test-only dependency to a dependency; `libc` added
  for tests.
- `docs/environment-variables.md`: the key file rules, under Keys and
  encryption.
- Tests in `src/common.rs`, from upstream, changed for the stale `.pub`, plus
  unreadable and invalid private keys leaving both files untouched.

### hbbs: punch request log capped, peer IDs at most 253 bytes (2026-11-04)

Issue #5. Ported from upstream rustdesk-server commit 5e37f45, which came after
this fork's base.

- The log behind the `punch-requests` admin command keeps at most
  `MAX_PUNCH_REQUESTS` entries (default 100000; `0` keeps none) and drops the
  oldest. Before, every punch request that was not a recent duplicate was
  added and nothing was ever removed.
- Peer IDs over 253 bytes are refused: `RegisterPk` over UDP, TCP and
  WebSocket answers `UUID_MISMATCH`, as it does for IDs under 6, before the
  per-ID registration lock is taken; UDP `RegisterPeer` gets no reply; a punch
  hole request answers `ID_NOT_EXIST`. Before, IDs had only a minimum length.
- `docs/environment-variables.md`: `MAX_PUNCH_REQUESTS`.
- Tests: a unit test for the cap in `src/rendezvous_server.rs`; in
  `tests/stream_registration.rs`, a 254-byte ID refused on each path and a
  253-byte one accepted.

### hbbs: `always-use-relay` leaves the relay list alone (2026-11-04)

Issue #4. Based on a fix proposed upstream by @jahvari, rustdesk-server PR 716.

- The admin console command `always-use-relay` / `aur` only sets the flag.
  Before, it also passed its argument to the relay server list, so `aur Y`
  replaced the list with "Y", which is not a valid server and left the list
  empty. Its help line now shows the argument: `always-use-relay(aur) [Y|N]`.
- New test `tests/admin_console.rs`.

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
