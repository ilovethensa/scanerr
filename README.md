# scanerr

A Minecraft server discovery engine that scans the internet for servers, collects their metadata, and provides a web UI to browse them.

## Binaries

- **`scaner`** — Masscan-based IP scanner (port 25565). Starts random, then prioritizes high-yield subnets.
- **`status`** — Pings discovered IPs for Minecraft server info (version, players, plugins, etc).
- **`webui`** — Actix-web frontend to browse servers and players.

## Setup

```sh
cargo build --release
```

Requires SQLite and [Masscan](https://github.com/robertdavidgraham/masscan) installed at `/usr/bin/masscan`.

## Usage

Run each binary in order:

```sh
./target/release/scaner    # discover IPs
./target/release/status    # fetch server metadata
./target/release/webui     # browse at http://127.0.0.1:8080
```
