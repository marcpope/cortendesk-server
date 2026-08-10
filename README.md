# CortenDesk Server

ID/rendezvous (`hbbs`) and relay (`hbbr`) servers for RustDesk clients.

This is a fork of [rustdesk-server](https://github.com/rustdesk/rustdesk-server),
based on release 1.1.16, with one change that matters: **signed-in clients can
connect.**

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
- `hbbr` is untouched. Clients never run this exchange against the relay.
- WebSocket connections are untouched. Clients skip the exchange there because
  the transport handles encryption, so offering it would only confuse them.
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

## Building

```bash
git clone --recurse-submodules https://github.com/marcpope/cortendesk-server.git
cd cortendesk-server
cargo build --release
```

`hbbs`, `hbbr` and `cortendesk-utils` land in `target/release`.

```bash
cargo test          # includes an end-to-end test of the handshake
```

## Licence

AGPL-3.0-only, inherited from rustdesk-server. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

RustDesk is a trademark of its owners. This project is not affiliated with,
endorsed by, or supported by the RustDesk project. Do not report problems with
these builds to them — [open an issue
here](https://github.com/marcpope/cortendesk-server/issues).
