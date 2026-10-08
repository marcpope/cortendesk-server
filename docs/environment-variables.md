# Configuration & Environment Variables

This document is the single reference for every option that the CortenDesk
Server binaries (`hbbs`, `hbbr`) understand: command‑line flags, environment
variables, and configuration files. They are the same options upstream
rustdesk-server takes, plus the device policy variables listed under `hbbs`.

> **TL;DR** — For most people the command‑line flags shown by `hbbs --help` /
> `hbbr --help` are all you need. Environment variables are an alternative way to
> set the same options, plus a handful of extra tuning knobs that have no flag.

---

## How configuration is loaded

Both servers read their configuration from the following sources. For
**`hbbs`** the order of precedence, from highest to lowest, is:

1. **Command‑line flag** (e.g. `-p 21116`, `-k mykey`)
2. **`--config <file>`** — an INI file passed with `-c`/`--config`
3. **`.env`** — an INI file named `.env` in the working directory
4. **Inherited process environment** — variables exported before launch

A value set by a higher source overrides the same value from a lower one. Under
the hood every source is turned into a process environment variable, and the
code then reads that variable — so "flag", "config file" and "env var" are just
three ways to set the same thing.

For **`hbbr`** the precedence is: **flag** (`-b`, `-p`, `-k`) → **`.env`** →
**inherited environment**.

`RUST_LOG` is an exception to these rules. Both binaries initialize logging
before loading `.env` (or `hbbs`'s `--config` file), so `RUST_LOG` must be set
in the inherited process environment.

---

## `hbbs` — ID / rendezvous server

| Variable | CLI flag | Default | Description |
|---|---|---|---|
| `KEY` | `-k`, `--key` | `-` | Public key clients must use, a base64 secret key, or `-` / `_` to load or generate a key pair (`id_ed25519`, `id_ed25519.pub`). `-` and `_` have the same behavior, so explicitly passing `-k _` to `hbbs` is unnecessary. An explicitly empty value disables key validation; see [Keys](#keys-and-encryption). |
| `BIND` | `-b`, `--bind` | all interfaces | **Available since 1.1.1.** Local IPv4 or IPv6 address on which all `hbbs` TCP, UDP, and WebSocket listeners bind. This does not change the addresses advertised to clients. Supported by `--config`, `.env`, and the inherited environment. |
| `PORT` | `-p`, `--port` | `21116` | Main TCP/UDP listening port. `hbbs` also binds `PORT-1` (NAT type test) and `PORT+2` (WebSocket). |
| `RELAY-SERVERS` | `-r`, `--relay-servers` | *(empty)* | Optional relay server override handed to clients, as comma-separated `host` or `host:port` values. Leave empty when `hbbr` uses the same address as `hbbs` and the standard port `21117`; clients derive it automatically. Set this only when the relay uses a different IP/hostname or a non-standard port. |
| `RMEM` | `-M`, `--rmem` | `0` (system default) | UDP receive‑buffer size in bytes. Raise the OS limit first: `sudo sysctl -w net.core.rmem_max=52428800`. |
| *(config file)* | `-c`, `--config` | *(none)* | Path to an extra INI config file (see precedence above). |
| `TEST_HBBS` 🅴 | *(none)* | *(auto)* | UDP self‑test target checked at start‑up. Set to `no` to skip the check (useful behind some NATs/proxies), or to an explicit `host:port`. |
| `ALWAYS_USE_RELAY` 🅴 | *(none)* | `N` | `Y` forces every session through a relay (disables direct/hole‑punched connections). At runtime, send `always-use-relay Y` or `always-use-relay N` to the `hbbs` [loopback console](#runtime-console). |
| `DB_URL` 🅴 | *(none)* | `./db_v2.sqlite3` | Path/URL of the SQLite database file. See [Database](#database). |
| `MAX_DATABASE_CONNECTIONS` 🅴 | *(none)* | `1` | Size of the SQLite connection pool. |
| `CORTENDESK_CONSOLE_URL` | *(none)* | *(empty)* | Base URL of a CortenDesk console, for device policy. See the [README](../README.md#device-policy-from-a-cortendesk-console). |
| `CORTENDESK_SERVER_SECRET` | *(none)* | *(empty)* | Secret shared with that console. Policy stays off unless this and `CORTENDESK_CONSOLE_URL` are both set. |
| `CORTENDESK_POLICY_INTERVAL` | *(none)* | `5` | Seconds between policy fetches, 1 to 300. |

🅴 = set through the inherited process environment.

> `PORT_FOR_API` / `KEY_FOR_API` have no effect on this server.

---

## `hbbr` — relay server

| Variable | CLI flag | Default | Description |
|---|---|---|---|
| `KEY` | `-k`, `--key` | *(empty)* | The empty default intentionally disables relay key validation, avoiding key-pair setup and mismatch failures. To enable relay key validation, use the same non-empty key as `hbbs`; `-` / `_` have the same behavior and load or generate a key pair. An empty key allows clients without a matching key to use the relay, so choose this tradeoff deliberately on an exposed server. |
| `BIND` | `-b`, `--bind` | all interfaces | **Available since 1.1.1.** Local IPv4 or IPv6 address on which the relay TCP and WebSocket listeners bind. Supported by `.env` and the inherited environment; `hbbr` does not support `--config`. |
| `PORT` | `-p`, `--port` | `21117` | Relay listening port. `hbbr` also binds `PORT+2` for WebSocket relay. **Note:** when set via the `PORT` env var (not `-p`), `hbbr` listens on `PORT + 1`, so a shared `PORT=21116` makes `hbbs`=21116 and `hbbr`=21117. |

### Relay bandwidth / QoS

These have no CLI flag and can also be changed through the `hbbr`
[loopback console](#runtime-console) (`tb`, `sb`, `ls`, `dt`, `t`, …; send `h`
for help).

| Variable | Default | Unit | Description |
|---|---|---|---|
| `SINGLE_BANDWIDTH` | `128` | Mb/s | Normal maximum bandwidth for each relay connection. |
| `TOTAL_BANDWIDTH` | `1024` | Mb/s | Aggregate bandwidth cap shared by all relay connections. |
| `LIMIT_SPEED` | `32` | Mb/s | Per-connection cap applied after a connection is downgraded, and to IPs in `blacklist.txt`. |
| `DOWNGRADE_THRESHOLD` | `0.66` | ratio (0–1) | Fraction of `SINGLE_BANDWIDTH` that a connection's lifetime-average throughput must exceed to trigger downgrade. |
| `DOWNGRADE_START_CHECK` | `1800` | seconds | Delay before a connection becomes eligible for the lifetime-average downgrade check. |

Downgrade is decided independently for each connection; it does **not** check
aggregate relay congestion. After `DOWNGRADE_START_CHECK`, a connection is
capped to `LIMIT_SPEED` once its average throughput since it started exceeds
`SINGLE_BANDWIDTH * DOWNGRADE_THRESHOLD`. A lone transfer can therefore be
downgraded even when the relay is otherwise idle. `TOTAL_BANDWIDTH` is a
separate aggregate cap.

These may also be placed in `.env` using the uppercase spellings shown above
(e.g. `SINGLE_BANDWIDTH=256`).

### Blocklists / blacklists (files, not env vars)

`hbbr` reads two optional files from its working directory at start‑up:

* **`blacklist.txt`** — IPs that are **bandwidth‑limited** (one IP per line;
  anything after the first space on a line is ignored).
* **`blocklist.txt`** — IPs that are **refused** outright.

Both can also be edited live through the `hbbr` loopback console (`ba`/`br`,
`Ba`/`Br`).

### Runtime console

The runtime consoles are TCP command transports built into the services; they
are not `cortendesk-utils` commands or interactive standard-input consoles. A
connection from a loopback address is treated as a single console command:

```bash
# hbbs: toggle forced relay on PORT-1 (21115 by default)
printf 'always-use-relay Y' | nc 127.0.0.1 21115

# hbbs: show the device policy state
printf 'policy' | nc 127.0.0.1 21115

# hbbr: list commands on its relay PORT (21117 by default)
printf 'h' | nc 127.0.0.1 21117
```

Use the corresponding configured ports if you changed `PORT`.

---

## Database

At runtime the database location comes from **`DB_URL`** (default
`./db_v2.sqlite3`). If unset, `hbbs` creates the SQLite file in its working
directory.

> **Do not confuse `DB_URL` with `DATABASE_URL`.** The `DATABASE_URL` entry in
> the repository's `.env` is used **only at compile time** by `sqlx` to check SQL
> queries; it is **not** read by the running server. Setting `DATABASE_URL` on a
> running server has no effect — use `DB_URL`.

---

## Logging

Both binaries use `flexi_logger`, which honours the standard **`RUST_LOG`**
environment variable (default level `info`). Set it in the process environment
before launching the binary. A value in `.env` or `hbbs`'s `--config` file is
loaded too late and has no effect on logging.

```bash
RUST_LOG=debug hbbs
```

---

## Keys and encryption

The `KEY` / `-k` value can be:

* a **public key** string — clients must present the matching key;
* a **base64‑encoded 64‑byte secret key** — the server derives the public key
  from it;
* **`-` or `_`** — the server loads a key pair from the working directory or
  generates one on first start, writing `id_ed25519` (private) and
  `id_ed25519.pub` (public);
* **empty** — key validation is disabled. `hbbs` still loads or generates key
  files for signing but deliberately leaves its active validation key empty;
  `hbbr` neither loads nor generates a key. Both services then accept clients
  without validating a key. This is the intentional `hbbr` default; use a
  non-empty value when relay key validation is required.

`hbbs` defaults to `-`, so it already loads or generates a key pair without an
explicit `-k _`. `hbbr` intentionally defaults to an empty key to avoid
key-pair setup and mismatch failures. Leave it empty for the default mode
without key validation. To enable relay key validation, give it the same
non-empty key as `hbbs`; both services can reuse key material from a shared
working directory. The `_` value is not a stricter mode than `-` in the current
implementation.

To supply your own key pair, place `id_ed25519` and `id_ed25519.pub` in the
process's **current working directory** before first start. That directory may
differ from the directory containing the executable. In the CortenDesk Server
image the working directory is `/root`.

---

## Docker image

The image (`ghcr.io/marcpope/cortendesk-server`, also on Docker Hub as
`marcpope/cortendesk-server`) contains the binaries and nothing else. It runs
`hbbs` by default; set the container command to `hbbr` for the relay. It has no
convenience variables of its own: upstream's `RELAY`, `ENCRYPTED_ONLY`,
`KEY_PUB` and `KEY_PRIV` belong to their s6 image and are ignored here. Pass
`-r`, `-k` and the rest on the command line instead.

Any variable from the tables above can be passed through the container's
environment (e.g. `-e ALWAYS_USE_RELAY=Y`, `-e RUST_LOG=debug`).

---

## Examples

### Command line — non-standard ports

```bash
# Tell clients where the relay listens because it is not using port 21117.
hbbs -p 22116 -r rustdesk.example.com:22117
hbbr -p 22117
```

### `.env` file (working directory)

```ini
# Non-standard ports shared by both binaries; hbbr listens on PORT+1.
relay-servers=rustdesk.example.com:22117
PORT=22116
```

### docker-compose

```yaml
services:
  hbbs:
    image: ghcr.io/marcpope/cortendesk-server:1
    command: hbbs -r rustdesk.example.com:21117
    environment:
      - ALWAYS_USE_RELAY=Y
      - RUST_LOG=info
    ports: ["21115:21115", "21116:21116", "21116:21116/udp"]
    volumes: ["./data:/root"]
    restart: unless-stopped

  hbbr:
    image: ghcr.io/marcpope/cortendesk-server:1
    command: hbbr
    environment:
      - SINGLE_BANDWIDTH=256
    ports: ["21117:21117"]
    volumes: ["./data:/root"]
    restart: unless-stopped
```

Leave 21118/21119 (WebSocket) unpublished unless you have RustDesk clients in
WebSocket mode. Then put them behind a reverse proxy that sets `X-Real-IP`:
hbbs and hbbr take the client address from that header on WebSocket
connections, so a directly exposed port lets a client claim any address.


### systemd

```ini
[Service]
Environment=ALWAYS_USE_RELAY=Y
Environment=RUST_LOG=info
ExecStart=/usr/bin/hbbs
```

---

## Port reference

| Port | Proto | Server | Purpose |
|---|---|---|---|
| 21115 | TCP | hbbs | NAT type test (`PORT-1`) |
| 21116 | TCP + UDP | hbbs | ID registration / rendezvous / hole punching (`PORT`) |
| 21117 | TCP | hbbr | Relay (`hbbr PORT`) |
| 21118 | TCP | hbbs | WebSocket rendezvous (`PORT+2`) |
| 21119 | TCP | hbbr | WebSocket relay (`hbbr PORT+2`) |

Ports 21118/21119 are only needed for the web client; you can omit them
otherwise.

On those two ports both servers take the client address from the `X-Real-IP` or
`X-Forwarded-For` header when one is present, without checking it (upstream
issue #634). Put them behind a reverse proxy that sets these headers, and do not
let clients reach them directly. The device policy does not use these headers.
