# CortenDesk Server

ID/rendezvous (`hbbs`) and relay (`hbbr`) servers for RustDesk clients.

This is a fork of [rustdesk-server](https://github.com/rustdesk/rustdesk-server),
in sync with upstream release 1.1.17, with two changes that matter:
**signed-in clients can connect**, and **RustDesk 1.5 clients can connect over
WebRTC** (since 1.2.0).

It is a drop-in replacement. Same binaries, same ports, same command-line flags,
same data files — point your existing compose file at these images and nothing
else changes.

## Why this fork exists

RustDesk clients from 1.4.1 onwards encrypt their signalling channel whenever
they are signed in to an API server, because the access token travels over it.
The client opens that exchange by waiting for the server to send it a signed
key. The open-source `hbbs` has no code to send one, so the client waits, times
out after 18 seconds, and reports:

```
Failed to secure tcp: deadline has elapsed
```

Every connection *from* a signed-in client fails this way — address book,
recents, or a manually typed ID, direct or relayed. Sign out and the same client
connects immediately, because a signed-out client has no token and skips the
exchange. That is the whole difference, and it makes the address book — the
reason to sign in at all — unusable.

This fork implements the server side of that exchange. A signed-in client
negotiates an encrypted channel and connects normally, with no client-side
workarounds and no settings to change.

Clients that do not encrypt signalling are unaffected: the offer is sent, they
skip past it (RustDesk clients have ignored unsolicited key-exchange frames
since 1.2.0), and the connection carries on in plain text exactly as before.

## What is different from upstream

- `hbbs` completes the signalling key exchange on plain TCP connections, and
  encrypts the rest of the connection once it has. Requires a server key pair,
  which is the default (`-k _`, or the generated `id_ed25519`); with no key
  there is nothing to sign the offer with, so nothing is offered.
- Clients never run this exchange against the relay (`hbbr`).
- WebSocket connections are untouched. Clients skip the exchange there because
  the transport handles encryption, so offering it would only confuse them.
- WebRTC signalling for RustDesk 1.5 clients: `hbbs` passes the WebRTC offer,
  answer and ICE candidates between the two machines, so a client with
  `enable-webrtc` on can connect over WebRTC. Upstream `hbbs` drops them and
  those clients fall back to their other transports. Only on encrypted
  connections, and only between the two machines in the request.
- Desktop clients can register over WebSocket or TCP and stay online, so a
  client can use the server through port 443 alone (since 1.3.0). Upstream
  `hbbs` refuses these registrations. See
  [WebSocket desktop clients](#websocket-desktop-clients).
- Optional device policy from a CortenDesk console: refuse devices the
  console has not approved, and devices marked incoming-only. Off unless
  configured; see below.
- Packaging trimmed to what is published here: Docker images and static Linux
  binaries. Upstream's Debian packaging, Windows installer UI, s6 image and
  Kubernetes example are not carried.

Full detail, with dates, is in [CHANGES.md](CHANGES.md).

## Running it

```yaml
services:
  hbbs:
    image: ghcr.io/marcpope/cortendesk-server:1
    command: hbbs -r relay.example.com:21117
    ports: ["21115:21115", "21116:21116", "21116:21116/udp"]
    volumes: ["./data:/root"]
    restart: unless-stopped

  hbbr:
    image: ghcr.io/marcpope/cortendesk-server:1
    command: hbbr
    ports: ["21117:21117"]
    volumes: ["./data:/root"]
    restart: unless-stopped
```

Leave 21118/21119 (WebSocket) unpublished unless you have RustDesk clients in
WebSocket mode. Then put them behind a reverse proxy that sets `X-Real-IP`:
hbbs and hbbr take the client address from that header on WebSocket
connections, so a directly exposed port lets a client claim any address.


Also published to `docker.io/marcpope/cortendesk-server`. Static `linux/amd64`
and `linux/arm64` binaries are attached to each
[release](https://github.com/marcpope/cortendesk-server/releases), with
`cortendesk-server-vX.Y.Z-src.tar.gz`, the complete source including the
`libs/hbb_common` submodule. GitHub's own "Source code" archives leave the
submodule out and do not build.

### Coming from rustdesk-server

Stop the containers, change the image, start them again. Keep the same `./data`
volume: the key pair (`id_ed25519`, `id_ed25519.pub`) and the peer database
(`db_v2.sqlite3`) are read as-is, so device IDs and keys survive and clients need
no reconfiguration.

Going back is the same move in reverse — nothing in the data directory changes
format. Signed-in clients simply stop connecting again.

## Configuration

Flags, environment variables and `.env` / `--config` files work as they do
upstream; `hbbs --help` and `hbbr --help` list the flags. Since 1.1.1 both
servers take `-b` / `BIND` to listen on one local IPv4 or IPv6 address instead
of all interfaces. Every option is in
[docs/environment-variables.md](docs/environment-variables.md).

Many machines behind one public IP: `hbbs` lets one IP register 300 distinct
IDs a day and 30 registrations in a row, after which new machines from it stay
offline ("ID does not exist"). Since 1.3.1 both are settings:
`MAX_NEW_IDS_PER_IP` / `--max-new-ids-per-ip` and
`MAX_REGISTER_BURST_PER_IP` / `--max-register-burst-per-ip`.

## Device policy from a CortenDesk console

Since 1.1.0 `hbbs` can enforce the device policy set in a
[CortenDesk](https://github.com/marcpope/cortendesk) console. The CortenDesk
image runs this server inside it and wires this up on its own. For a separate
`hbbs`, set on the `hbbs` container:

| Variable | Meaning |
|---|---|
| `CORTENDESK_CONSOLE_URL` | Base URL of the console as `hbbs` reaches it, e.g. `https://desk.example.com` |
| `CORTENDESK_SERVER_SECRET` | Shared secret. Same value as `CORTENDESK_SERVER_SECRET` on the console |
| `CORTENDESK_POLICY_INTERVAL` | Seconds between policy fetches. Default `5`, range 1 to 300 |

Both of the first two must be set, or the link stays off and `hbbs` behaves as
1.0.0. `hbbr` needs nothing.

What it does:

- Pulls the policy from `GET /api/server/policy` every interval and enforces
  it from memory. Unchanged policy is a 304.
- In approved-only mode, a device the console has not approved cannot start a
  session and cannot be reached. It still registers, so it shows up in the
  console as pending.
- A device marked incoming-only can be reached but cannot start a session, in
  either mode.
- Refused clients see why: "This device is not approved on this server...",
  "This device is set to incoming only...", or "The remote device is not
  approved on this server."
- Posts the LAN address a device reports during connection setup to
  `POST /api/server/local-addrs`, so the console can show it.

The console is the source of truth. If it is unreachable, `hbbs` keeps the
last policy it got, and keeps it across restarts in `policy_snapshot.json`.
With no policy at all, on a first start with the console down, every device is
allowed and the log says so. This is deliberate: failing closed would stop
every session on the server whenever the console is down.

### How `hbbs` knows who is asking

A connection request names the device to reach, not the device asking. `hbbs`
identifies the sender by, in order:

1. a ticket signed with the shared secret, which the console's web client sends;
2. the console access token a signed-in RustDesk client sends;
3. its IP address, matched against devices that registered from that address
   in the last 30 seconds, not counting the target. On WebSocket through a
   proxy listed in `TRUSTED_PROXIES`, that is the address the proxy names; the
   same address is recorded when a device registers over WebSocket.

Signed-in clients are identified exactly. The IP match is weak: behind a
shared NAT, or a proxy that rewrites source addresses (Docker's userland
proxy, IPv6 port publishing, Docker Desktop), every client looks like every
other one behind it. So in approved-only mode it is off unless the console
turns it on ("Identify signed-out devices by IP address"), and only signed-in
clients and the web client can start sessions. Open mode still uses it to stop
incoming-only devices, which is best effort for signed-out clients.

### Limits

- Sessions already running are not cut. A device that loses approval cannot
  start or receive new ones after the next fetch.
- `hbbr` does not see the policy. It pairs two connections that present the
  same uuid and the server key. Stock clients only learn that uuid through
  `hbbs`, so the policy covers them; modified clients that agree on a uuid some
  other way can still use the relay.

## WebSocket desktop clients

Since 1.3.0, RustDesk desktop clients (1.4 and later) can use this server over
WebSocket only, so everything goes through port 443. Upstream `hbbs` answers
their registration with `NOT_SUPPORT`, so they never show as online. The same
registration over plain TCP serves clients that use a proxy or have
`disable-udp` set. Contributed by vk2amv.

On the client:

- `allow-websocket` = `Y` (Settings → Network → Use WebSocket).
- ID server and relay server as a hostname, not an IP address. With a
  hostname the client connects to `ws(s)://<host>/ws/id` and
  `ws(s)://<host>/ws/relay` on the default port; with an IP address it goes
  to `ws://<ip>:21118` and `:21119` directly, without TLS.
- API server `https://<host>`: the client uses `wss://` only when the API
  server is https. With `http://` it uses `ws://` on port 80.
- The key as usual.

On the server:

- A reverse proxy with TLS on port 443:
  - `/ws/id` to `hbbs` port 21118, `/ws/relay` to `hbbr` port 21119;
  - HTTP/1.1 with the `Upgrade` and `Connection` headers passed on;
  - a read timeout of at least 120 seconds;
  - `X-Forwarded-For` set to the address the client connected from, replacing
    what the client sent (nginx: `proxy_set_header X-Forwarded-For
    $remote_addr;`). Appending also works, since the servers read it from the
    right. `X-Real-IP` is not used.
- `TRUSTED_PROXIES` on both `hbbs` and `hbbr`: the address the proxy connects
  from, e.g. `127.0.0.1/32` when it runs on the same host or in the same
  container. The default is empty: no proxy is trusted, the header is ignored,
  and every WebSocket client looks like the proxy to rate limits and the
  device policy.
- Ports 21115 to 21117 can stay closed to these clients.

How a registration lives: the client registers once per connection. `hbbs`
answers with `keep_alive` 20 seconds, sends an empty heartbeat every 10
seconds, and drops a connection silent for 30. The newest registration of an
ID wins. Sessions to or from a WebSocket client go through the relay.

## Building

```bash
git clone --recurse-submodules https://github.com/marcpope/cortendesk-server.git
cd cortendesk-server
cargo build --release
```

`hbbs`, `hbbr` and `cortendesk-utils` land in `target/release`.

```bash
cargo test          # end-to-end tests of the handshake and the device policy
```

## Licence

AGPL-3.0-only, inherited from rustdesk-server. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

RustDesk is a trademark of its owners. This project is not affiliated with,
endorsed by, or supported by the RustDesk project. Do not report problems with
these builds to them — [open an issue
here](https://github.com/marcpope/cortendesk-server/issues).
