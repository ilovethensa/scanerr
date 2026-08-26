# scanerr — Agent Instructions

Shodan-like service scanner for homelabbers. Written in Rust, deployed as Docker containers on a Proxmox VM (`root@192.168.1.111`, VM at `192.168.1.202`).

## Architecture

Four-stage pipeline, each a separate binary mode:

1. **scan** — masscan sweeps Bulgarian CIDR ranges (from `ranges.txt`), inserts alive hosts into `queue_host_scans`
2. **probe** — claims hosts from queue, runs masscan per-host for deep port scan, inserts open ports into `queue_service_probes`, identifies protocol, fingerprints each service
3. **enrich** — fetches favicons, computes hashes, enriches service data inline during probe or as a separate stage
4. **serve** — web UI (Tera templates) and JSON API on port 8080

## Project Structure

```
src/
├── main.rs                  # CLI entry point (clap), spawns scan/probe/serve/enrich/all + test-* commands
├── lib.rs                   # Library root: re-exports all public modules
├── config.rs                # TOML config loader (scanerr.toml), SCANERR_DB env override
├── db.rs                    # Postgres connection pool, SQLx migration runner
├── models.rs                # Protocol enum, ServiceData (JSONB), protocol payload structs, DB row types
├── masscan.rs               # masscan wrapper (stage1: CIDR sweep, stage2: per-host)
├── queue.rs                 # LeasedQueue: claim/heartbeat/complete/sweep, insert helpers
├── query.rs                 # Shodan-style query parser → PostgreSQL WHERE clauses
├── evidence.rs              # Normalizes ServiceData into flat BTreeMap for fingerprint matching
├── signatures.json          # Legacy JSON signature database (being replaced by YAML)
├── fingerprint/
│   ├── mod.rs               # Engine struct: loads signatures, identifies best match
│   ├── signature.rs         # Signature/matcher types, compiled regex, operator enum
│   ├── loader.rs            # Recursive YAML loader from signatures/ directory
│   └── score.rs             # Scoring engine: weighted match → confidence percentage
├── probe/
│   ├── mod.rs               # Module re-exports
│   ├── engine.rs            # ProtocolProbe trait + ProbeRegistry: banner-first dispatcher
│   ├── dispatch.rs          # Orchestration: probe() with DB, upsert_service(), fingerprint call
│   ├── http/
│   │   ├── mod.rs           # probe_http(): manual redirect following (3 hops), HTTPS detection
│   │   ├── parse.rs         # HTML parsing: title extraction, SHA256 hashing
│   │   └── tech.rs          # Technology fingerprinting from headers/body (30+ techs)
│   ├── ssh.rs               # SSH probe: KEXINIT handshake, host key, fingerprint
│   ├── tls.rs               # TLS probe: tokio-rustls, X509 cert extraction (CN, self-signed)
│   ├── ftp.rs               # FTP probe: SYST/FEAT/HELP, anonymous login + PASV LIST
│   ├── smtp.rs              # SMTP probe: EHLO extensions, STARTTLS detection
│   ├── imap.rs              # IMAP probe: CAPABILITY from greeting, NOOP/LOGOUT
│   ├── mysql.rs             # MySQL probe: server greeting parser (v10/v9)
│   ├── mqtt.rs              # MQTT probe: CONNECT v3.1.1, CONNACK, $SYS topic discovery
│   ├── pptp.rs              # PPTP probe: SCCRQ/SCCRP handshake, magic cookie validation
│   ├── sccp.rs              # Cisco SCCP probe: RegisterReq/RegisterAck, device type/firmware extraction
│   ├── geoip.rs             # MaxMind GeoIP lookup (country code, ASN)
│   ├── rndns.rs             # Reverse DNS resolver (placeholder)
│   └── raw.rs               # Raw banner capture with basic SSH/FTP detection
├── enrich/
│   ├── mod.rs               # Enrichment dispatcher (Favicon kind)
│   └── favicon.rs           # Favicon fetch + SHA256 + mmh3 hash (Shodan-compatible)
└── serve/
    ├── mod.rs               # Axum router: index, search, host, service, JSON API routes
    ├── routes.rs            # Route handlers: index, search, host detail, service detail
    └── state.rs             # AppState: PgPool + Tera template engine

templates/
├── index.html               # Latest hosts table (Shodan-style dark theme)
├── host.html                # Host detail: expandable service cards with raw JSON
├── search.html              # Search results table
└── service.html             # Single service detail view

migrations/
├── 20260825000001_init.sql          # hosts, services, queue tables, indexes
└── 20260825010000_fix_unique_sni.sql # UNIQUE with COALESCE(sni, '')

signatures/
├── http/                    # YAML HTTP signatures (servers, erp, monitoring, power, isp)
│   ├── servers/             # nginx, Apache, IIS, LiteSpeed, Google GWS, CloudFront
│   ├── erp/                 # ERPNext
│   ├── monitoring/          # Wazuh
│   ├── power/               # Huawei solar inverters
│   └── isp/                 # IPACCT
└── ssl/                     # YAML TLS certificate signatures

tests/
├── integration.rs           # Queue integration tests (claim/heartbeat/sweep, backpressure)
├── probe.rs                 # Probe unit tests (mock HTTP, raw banner, timeouts)
├── enrich.rs                # Favicon enrichment tests (mock HTTP + real DB)
└── workflow.rs              # Full pipeline test: queue → probe → fingerprint → enrich → search

Root files:
├── scanerr.toml             # Main config (DB URL, scanner ports/rates, probe settings, web UI bind)
├── ranges.txt               # Bulgarian CIDR ranges with exclusions
├── docker-compose.yml       # Docker stack: postgres + scan + probe + enrich + serve containers
├── Dockerfile               # Multi-stage build: Rust 1.85 builder → Debian slim runtime
├── deploy.sh                # Build locally → SCP to VM → restart compose stack
└── signatures.json          # Legacy JSON signatures (superseded by signatures/ YAML)
```

## Key Design Decisions

### Queue System
- `queue_host_scans` and `queue_service_probes` use leased locking (`claimed_until` timestamp + `FOR UPDATE SKIP LOCKED`)
- Items are **deleted** after processing (`complete()`) — not reused
- `sweep()` handles stale leases: requeue if `attempts < max`, delete otherwise
- `backpressure_active()` pauses scan when probe queue depth exceeds `max_probe_queue_depth`

### Duplicate Prevention
- `queue_host_scans.ip` has UNIQUE constraint — `INSERT ... ON CONFLICT DO NOTHING`
- `queue_service_probes` has UNIQUE on `(ip, port, transport)`
- Service upsert uses a CTE that manually checks for existing rows to handle NULL `sni` correctly (NULL != NULL in SQL)
- Partial unique index on services: `CREATE UNIQUE INDEX ... ON services (host_id, port, transport, COALESCE(sni, ''))`

### Protocol Detection (`engine.rs`)
The `ProbeRegistry::dispatch()` runs a banner-first pipeline:

1. **Connect & read banner** (5s timeout via `read_banner()`)
2. **Banner matching** — every probe's `detects_banner()` is called; highest `probe_priority()` wins
3. **HTTP/TLS fallback** — if no probe matched: try plain HTTP → HTTPS → raw TLS cert via `try_http_fallback()`
4. **Active-only probes** — probes with `requires_probe_without_banner() → true` run as last resort (PPTP, MQTT, SCCP)
5. **Unknown** — `ServiceData::default()` with `kind: "unknown"`

Priority ordering: SSH=100, FTP/SMTP=90, IMAP/MySQL=80, PPTP/MQTT/SCCP=60

### HTTP Probe
- Disables auto-redirects, follows manually up to 3 hops
- Cross-port redirects followed (no port restriction)
- If redirect target fails (timeout/connection refused), returns data from first response
- Detects HTTPS rejection (status 400/495/496 with SSL/TLS keywords) and retries via `probe_https()`
- Null bytes stripped from body text (`\0` → removed) and from JSON before PostgreSQL insert (`sanitize_json_nulls()`)

### Fingerprint Engine
- YAML signature files in `signatures/` directory tree (http/, ssl/, ssh/)
- Each signature has matchers with operators (contains, icontains, regex, equals, startswith, endswith, hash_equals, exists)
- `Evidence` struct normalizes `ServiceData` into `BTreeMap<String, Vec<String>>` for matching
- Best match selected by weighted score, then priority; sets `product`, `version`, `confidence`, merges tags

### Data Sanitization
- `sanitize_json_nulls()` in `dispatch.rs` recursively removes `\0` from all JSON string values before DB insert
- PostgreSQL JSONB rejects `\u0000` — this is the safety net

## How to Add a New Protocol Probe

Every protocol probe follows a 3-step pattern. Here's the checklist:

### Step 1: Add types to `src/models.rs`

```rust
// 1a. Add variant to Protocol enum
pub enum Protocol {
    // ... existing variants ...
    Sftp,  // your new protocol
}

// 1b. Add to Protocol::as_str()
Protocol::Sftp => "sftp",

// 1c. Add to From<&str>
"sftp" => Protocol::Sftp,

// 1d. Create protocol-specific data struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SftpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    // ... other fields ...
}

// 1e. Add field to ServiceData
pub struct ServiceData {
    // ... existing fields ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sftp: Option<SftpData>,
}

// 1f. Add to ServiceData::default()
sftp: None,
```

### Step 2: Create probe file `src/probe/sftp.rs`

Follow the pattern of existing probes. Two categories:

**Banner-detected** (server sends first data — FTP, SSH, SMTP, IMAP, MySQL):
```rust
use anyhow::Result;
use crate::models::{Protocol, SftpData, ServiceData};
use super::engine::ProtocolProbe;

pub struct SftpProbe;

impl ProtocolProbe for SftpProbe {
    fn protocol(&self) -> Protocol { Protocol::Sftp }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("SSH-2.0-") && text.contains("sftp")
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        // Parse banner, run protocol-specific interaction, return ServiceData
        let mut data = ServiceData::default();
        data.kind = "sftp".into();
        data.banner = Some(String::from_utf8_lossy(banner).trim().to_string());
        data.sftp = Some(SftpData { version: None });
        data.tags = vec!["sftp".into()];
        Ok(data)
    }
}
```

**Active-only** (server sends nothing — PPTP, MQTT, SCCP):
```rust
impl ProtocolProbe for SftpProbe {
    fn protocol(&self) -> Protocol { Protocol::Sftp }
    fn requires_probe_without_banner(&self) -> bool { true }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        // Connect, send protocol-specific message, parse response
        let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
        stream.write_all(&build_probe_message()).await?;
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        // Validate response, parse, return ServiceData
        // ...
    }
}
```

### Step 3: Register the probe in `src/probe/engine.rs`

```rust
// 3a. Add import
use super::{/* ... existing ... */, sftp};

// 3b. Add enum variant
pub enum ProbeKind {
    // ... existing ...
    Sftp(sftp::SftpProbe),
}

// 3c. Add match arms to ALL 4 ProtocolProbe method delegations:
//     protocol(), requires_probe_without_banner(), detects_banner(), probe()
//     Each needs a new match arm delegating to the inner probe.

// 3d. Add to ProbeRegistry::new() vec
ProbeKind::Sftp(sftp::SftpProbe),

// 3e. Add to probe_priority()
Protocol::Sftp => 60,  // lower = tried later as fallback
```

### Step 4: Add module declaration to `src/probe/mod.rs`

```rust
pub mod sftp;
```

### Step 5: Verify

```sh
cargo check          # Must compile
cargo test           # Unit tests pass
cargo build          # Debug binary builds
./target/debug/scanerr test-probe <ip>:<port>  # Test against real host
```

### Priority guidelines

| Priority | Probes | When to use |
|----------|--------|-------------|
| 100 | SSH | Unique banner prefix, very reliable detection |
| 90 | FTP, SMTP | Text-based with distinctive greetings |
| 80 | IMAP, MySQL | Binary or text with clear protocol signatures |
| 60 | PPTP, MQTT, SCCP | Active-only or ambiguous, used as fallback |
| 0 | Fallback | Catch-all |

## Deployment

### VM Setup
- Proxmox VM: Ubuntu, 5GB RAM, 2 vCPU, IP `192.168.1.202`
- SSH direct to VM (key-based auth from host)
- Docker Compose: postgres, scan, probe, enrich, serve containers (host networking)

### deploy.sh
Builds locally, transfers image to VM, restarts containers:
```sh
./deploy.sh
```
- Builds Docker image locally (no compilation in VM)
- `docker save` → gzip → SCP to VM → `docker load`
- Copies source files, restarts compose stack

### Config
- `scanerr.toml` — main config (database URL, scanner ports/rates, probe settings, signatures dir)
- `ranges.txt` — Bulgarian CIDR ranges with exclusions (government, critical infra, research)
- `ranges_file` field in config is optional; missing file = warning, empty ranges

## Running Locally

```sh
# Test probe (no DB needed)
cargo build
./target/debug/scanerr test-probe 71.69.195.233:1723   # PPTP
./target/debug/scanerr test-probe 1.1.1.1:80           # HTTP
./target/debug/scanerr test-probe 1.1.1.1:443          # HTTPS
./target/debug/scanerr test-probe 45.149.234.1:2000    # SCCP

# Test deep scan (needs masscan + root)
sudo ./target/debug/scanerr test-scan 1.1.1.1

# Full stack (needs PostgreSQL)
SCANERR_DB="postgres://..." ./target/debug/scanerr all
```

## Testing Checklist

Before deploying any probe/protocol change:
1. `cargo check` — must compile cleanly
2. `cargo test` — run unit tests
3. `cargo build` — build debug binary
4. `./target/debug/scanerr test-probe <known-ip>:<port>` — verify on a real host
5. Check output has no null bytes, no crashes, correct `kind` field
6. Then `./deploy.sh`

## Common Issues

- **`\u0000` PostgreSQL error**: Null bytes in JSON. Fix: strip in `sanitize_json_nulls()` and in individual probes
- **Duplicate services**: Use COALESCE-based unique index for NULL sni handling
- **Probe stalling**: 10s timeout per probe call in main loop
- **OOM on VM**: Reduce concurrency in docker-compose resource limits
- **Slow queue queries**: VM disk I/O is slow; 15s claim queries are expected
