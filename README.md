# scanerr

A Shodan-like service scanner for homelabbers. Discovers open ports, fingerprints services, grabs deep metadata, and serves a searchable web UI and JSON API.

## Features

- **Two-Stage Discovery**: Broad CIDR sweep → deep per-host port scan
- **Service Fingerprinting**: HTTP/TLS/SSH/FTP detection with signature matching
- **Enrichment Pipeline**: Favicon fetching with Shodan-compatible mmh3 hashing
- **JSONB Search**: Fast PostgreSQL JSONB containment queries
- **Web UI**: Searchable interface with JSON API

## Quick Start

### Using Docker Compose

```sh
docker compose up -d
```

### Manual Setup

1. Install dependencies:
   - [masscan](https://github.com/robertdavidgraham/masscan)
   - PostgreSQL 14+

2. Create the database:
   ```sh
   createdb scanerr
   ```

3. Build and run:
   ```sh
   cargo build --release
   ./target/release/scanerr all
   ```

## Usage

The binary supports multiple roles:

```sh
# Run all stages (default for homelab)
scanerr all

# Run specific stages
scanerr scan      # Discovery only (requires root for masscan)
scanerr probe     # Service fingerprinting
scanerr enrich    # Enrichment (favicons, screenshots)
scanerr serve     # Web UI and API
```

## Configuration

Edit `scanerr.toml` or use environment variables:

```sh
export SCANERR_DB="postgres://user:pass@host/dbname"
```

## Query Syntax

Search services using Shodan-style filters:

```
port:443                          # By port
tag:iot                           # By tag
http.title:"Proxmox VE"          # By HTTP title
ssl.cert_cn:"bank.com"           # By TLS certificate
country:DE                        # By country code
```

## API

```sh
# Search API
curl "http://localhost:8080/api/search?q=port:443"

# Service detail
curl "http://localhost:8080/api/service/123"
```

## Development

```sh
# Run tests
cargo test

# Run with custom config
RUST_LOG=debug SCANERR_DB="postgres://..." cargo run -- serve
```

## License

MIT
