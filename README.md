# CortenDesk Server

ID/rendezvous (`hbbs`) and relay (`hbbr`) servers for RustDesk clients.

This is a fork of [rustdesk-server](https://github.com/rustdesk/rustdesk-server),
based on release 1.1.16. It adds encrypted signalling for signed-in clients
and persistent desktop registration over TCP and WebSocket.

It uses the same binaries, ports, and data-file formats. Reverse proxies on
non-loopback addresses must be configured as trusted proxies (see below).

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
- `hbbs` accepts desktop `RegisterPk` over TCP and WebSocket, maintains
  registration with application heartbeats, and routes incoming requests over
  the registered connection. WebSocket sessions use relay transport.
- WebSocket signalling skips the native key exchange; use WSS at your TLS
  reverse proxy. Clients never run this exchange against `hbbr`.
- Both listeners honour forwarded client-IP headers only from trusted proxies.
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
    ports: ["21115:21115", "21116:21116", "21116:21116/udp", "21118:21118"]
    volumes: ["./data:/root"]
    restart: unless-stopped

  hbbr:
    image: ghcr.io/marcpope/cortendesk-server:1
    command: hbbr
    ports: ["21117:21117", "21119:21119"]
    volumes: ["./data:/root"]
    restart: unless-stopped
```

Also published to `docker.io/marcpope/cortendesk-server`. Static `linux/amd64`
and `linux/arm64` binaries are attached to each
[release](https://github.com/marcpope/cortendesk-server/releases).

### Coming from rustdesk-server

Stop the containers, change the image, start them again. Keep the same `./data`
volume: the key pair (`id_ed25519`, `id_ed25519.pub`) and the peer database
(`db_v2.sqlite3`) are read as-is, so device IDs and keys survive and clients need
no reconfiguration.

Going back is the same move in reverse — nothing in the data directory changes
format. Signed-in clients simply stop connecting again.

## Desktop WebSocket mode (unreleased)

These changes are available in this source tree; build it to test them before
using a published image. In RustDesk desktop, enable **Settings → Network →
Use WebSocket** (`allow-websocket=Y`). Configure the ID/relay server hostname,
server public key, and HTTPS API-server URL as usual. RustDesk 1.4.9 uses that
HTTPS setting when constructing `wss://HOST/ws/id` and `wss://HOST/ws/relay`.

Proxy routes:

| Path | Upstream | Role |
| --- | --- | --- |
| `/ws/id` | `hbbs:21118` | Registration and signalling |
| `/ws/relay` | `hbbr:21119` | Relayed session data |

Forward HTTP/1.1 WebSocket Upgrade and Connection headers. Use a proxy idle
read timeout of at least 120 seconds. If HAProxy terminates TLS in front of
Nginx, preserve the trusted client-IP chain through both hops. Nginx must set
`X-Real-IP` or `X-Forwarded-For` to a verified client address rather than blindly
passing client-supplied values.

### Trusted proxies

Both `hbbs` and `hbbr` trust loopback (`127.0.0.0/8,::1/128`) by default. If Nginx
connects from a container-network address, add its actual source IP/CIDR:

```bash
hbbs --trusted-proxies '127.0.0.0/8,::1/128,172.20.0.5/32' -r relay.example.com:21117
hbbr --trusted-proxies '127.0.0.0/8,::1/128,172.20.0.5/32'
```

`TRUSTED_PROXIES` is the environment equivalent; the command-line setting takes
precedence. An empty setting trusts no proxies. Invalid CIDRs fail startup.
Untrusted or invalid forwarded headers leave the socket's real peer IP in use.
Forwarded IPs are used for identity checks and logging; connection routing uses
a separate internal ID and a reserved nonzero address correlation token.

### Registration lifecycle

- Successful stream registration returns `OK` with `keep_alive=20` seconds.
- The server sends empty application heartbeat messages every 10 seconds;
  clients echo them. A 30-second receive deadline expires silent connections.
- Heartbeats start only after successful registration, so temporary signalling
  connections receive their protocol response first.
- The newest successfully validated stream owns the device registration.
  Old heartbeats and disconnects cannot change its replacement's presence.
- Native UDP presence is tracked separately. A live stream takes routing
  priority; a live UDP registration can remain available after it disconnects.
- Outbound queues hold at most 64 messages. A full queue or a write taking more
  than five seconds terminates that stream; WS closure gets a bounded handshake.
- UUID/key validation and rate limits are shared across transports. A database
  write failure returns `SERVER_ERROR` without claiming the new identity.

The database schema and protobuf enum numbers are unchanged. This feature does
not add an API enrollment/sign-in requirement to the existing registration rules.

### Verification

`tests/stream_registration.rs` starts isolated `hbbs`/`hbbr` processes and checks
registration, repeated routing, shared IPv4/IPv6 addresses, reconnection,
heartbeat expiry, persistence failure, encrypted TCP, and all native/WS relay
combinations. Tests require permission to bind local sockets and a non-loopback
local interface for native relay connections (the relay reserves loopback TCP
for management commands). The idle test takes approximately 40 seconds.

## Building

```bash
git clone --recurse-submodules https://github.com/marcpope/cortendesk-server.git
cd cortendesk-server
cargo build --release
```

`hbbs`, `hbbr` and `cortendesk-utils` land in `target/release`.

```bash
cargo test --locked # includes real-socket signalling and relay tests
```

## Licence

AGPL-3.0-only, inherited from rustdesk-server. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

RustDesk is a trademark of its owners. This project is not affiliated with,
endorsed by, or supported by the RustDesk project. Do not report problems with
these builds to them — [open an issue
here](https://github.com/marcpope/cortendesk-server/issues).
