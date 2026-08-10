# Changes from rustdesk-server

This file is the statement of modifications required by section 5(a) of the
GNU Affero General Public License. It lists every change made to the original
work, with the date it was made.

**Base:** [rustdesk-server](https://github.com/rustdesk/rustdesk-server) release
`1.1.16`, commit `73523b3`, published 2026-07-21. Copyright of the original work
remains with its authors; see LICENSE and NOTICE.

Versions below are CortenDesk Server versions. They are numbered independently
of upstream so the two are never mistaken for each other.

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
