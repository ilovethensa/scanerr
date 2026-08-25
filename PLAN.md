# scanerr — Rebuild Plan v4: Self-Hosted Shodan Alternative

A Shodan-like service scanner for homelabbers. Discovers open ports, fingerprints services, grabs deep metadata, and serves a searchable web UI and JSON API. Designed for a single user running on 1 to N machines.

This document reflects the final architecture: a two-stage discovery pipeline (broad sweep → deep port scan), a pure schemaless JSONB document model for state/search, and strict relational tables for crash-safe queues.

---

## 1. Core Principles

| Principle | Implementation |
|---|---|
| **Single Binary, Multiple Roles** | `scanerr scan`, `scanerr probe`, `scanerr enrich`, `scanerr serve`, `scanerr all`. One Docker image, one codebase. |
| **Single Infrastructure Dep** | Postgres is the *only* dependency. It handles state, search (JSONB GIN indexes), and work queues (`SKIP LOCKED`). No Redis, no Elasticsearch. |
| **Two-Stage Discovery** | Stage 1 sweeps CIDRs for alive IPs on 2-3 ports. Stage 2 deep-scans alive IPs for all ports. Saves massive bandwidth and time. |
| **Shodan-Matching Data Model** | Services are stored as "Banners" (pure JSONB). The Rust probe just serializes its struct to JSON and saves it. No flat columns, no DB-level string parsing. |
| **DB-as-Queue** | Stages communicate only through leased Postgres queues. Crash-safe at-least-once. Horizontal scaling = copy binary + config, point at DB. |

---

## 2. Architecture & Runtime

### 2.1 The `scanerr` Binary

One binary, compiled with all features. Homelabbers run `scanerr all` (spawns 5 tokio tasks). Scale-out users run specific subcommands on different machines.

*   `scanerr scan`: Runs the two-stage discovery pipeline (sweeper + deep scanner).
*   `scanerr probe`: The fingerprinting worker. Drains the service queue, connects, upserts JSONB.
*   `scanerr enrich`: Heavy async work (favicons today, screenshots/RTSP tomorrow).
*   `scanerr serve`: Web UI and JSON API.
*   `scanerr all`: Runs all stages concurrently (the homelab default).

Privilege separation: only `scanerr scan` needs root (masscan raw sockets). All others run unprivileged.

### 2.2 The Pipeline Flow

1. **Stage 1: Broad Sweeper (`scanerr scan` loop 1)**
   * Runs `masscan` across configured CIDRs on just 3 ports (e.g., 22, 80, 443).
   * If a host responds on *any* port, it is "alive". Inserts the IP into `queue_host_scans`.
2. **Stage 2: Deep Port Scanner (`scanerr scan` loop 2)**
   * Claims batches of IPs from `queue_host_scans`.
   * Runs `masscan` against *that single IP* on the top 100 ports.
   * Every open port found is inserted into `queue_service_probes` for the probe workers.
3. **Stage 3: Probe (`scanerr probe`)**
   * Claims `ip:port` jobs from `queue_service_probes`.
   * Performs Reverse DNS, checks GeoIP, then sequentially tries: TCP connect → HTTP GET (via `reqwest`) → TLS Handshake (via `tokio-rustls`) → Raw banner read.
   * Structures data into the `ServiceData` enum, runs signature matching, and upserts the `services` row as a pure JSONB document.
4. **Stage 4: Enricher (`scanerr enrich`)**
   * Claims jobs from `queue_enrichments` (e.g., `favicon`).
   * Fetches the asset, saves it to disk (content-addressed), inserts a row in `service_assets`, and updates the JSONB `data` payload with the hash, re-running fingerprinting if necessary.
5. **Stage 5: Server (`scanerr serve`)**
   * Executes lightning-fast JSONB containment queries (`@>`) to find services, returning the raw JSONB directly to the UI/API exactly as Shodan does.

---

## 3. The Shodan-Matching Data Model

To make the schemaless approach work in Postgres, we use `JSONB` with a `jsonb_path_ops` GIN index. This index is specifically designed to answer `@>` (containment) queries instantly.

*   **No Flat Columns:** We stop extracting `title`, `tags`, and `product` into their own columns. They live entirely inside the `data` JSONB blob.
*   **No DB Regex/FTS:** We do not generate `tsvector` columns. All text searches are exact matches or JSONB array containment checks.
*   **The Rust Struct IS the Schema:** The `ServiceData` enum in Rust is serialized directly to the DB. Adding a new protocol or field requires zero database migrations—just update the Rust struct.

---

## 4. Database Schema

```sql
-- =========================================================
-- 1. HOSTS (The Machine Context)
-- =========================================================
CREATE TABLE hosts (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip           INET UNIQUE NOT NULL,
  
  -- Network Context (MaxMind ASN/City DBs)
  reverse_dns  TEXT,
  country_code TEXT,
  asn          INTEGER,       
  org          TEXT,          
  hostnames    TEXT[],         -- e.g., {"router.lan", "synology.com"}
  
  first_seen   BIGINT NOT NULL,
  last_seen    BIGINT NOT NULL
);

CREATE INDEX idx_hosts_country   ON hosts(country_code);
CREATE INDEX idx_hosts_asn       ON hosts(asn);
CREATE INDEX idx_hosts_org       ON hosts(org);
CREATE INDEX idx_hosts_hostnames ON hosts USING GIN(hostnames);

-- =========================================================
-- 2. SERVICES (The "Banners" - Pure JSONB like Shodan)
-- =========================================================
CREATE TABLE services (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  host_id    BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  
  port       INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport  TEXT NOT NULL DEFAULT 'tcp',
  sni        TEXT,                           -- Virtual Host / TLS SNI
  
  -- EVERYTHING lives in here. Matches Shodan's nested banner structure perfectly.
  data       JSONB NOT NULL,

  first_seen BIGINT NOT NULL,
  last_seen  BIGINT NOT NULL,

  UNIQUE(host_id, port, transport, sni) 
);

-- The GIN index makes EVERY field inside the JSONB searchable instantly.
CREATE INDEX idx_services_data ON services USING GIN(data jsonb_path_ops);
CREATE INDEX idx_services_host ON services(host_id);

-- =========================================================
-- 3. QUEUES (Crash-safe work - Relational)
-- =========================================================

-- Queue 1: Stage 1 -> Stage 2 (IPs that responded to broad sweep, need deep scan)
CREATE TABLE queue_host_scans (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip            INET NOT NULL,
  attempts      INT NOT NULL DEFAULT 0,
  claimed_until BIGINT,
  UNIQUE(ip)
);
CREATE INDEX idx_host_scans_unclaimed ON queue_host_scans(id) 
  WHERE claimed_until IS NULL;

-- Queue 2: Stage 2 -> Stage 3 (IP:Ports found by deep scan, need probing)
CREATE TABLE queue_service_probes (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip            INET NOT NULL,
  port          INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  transport     TEXT NOT NULL DEFAULT 'tcp',
  attempts      INT NOT NULL DEFAULT 0,
  claimed_until BIGINT,
  UNIQUE(ip, port, transport)
);
CREATE INDEX idx_service_probes_unclaimed ON queue_service_probes(id) 
  WHERE claimed_until IS NULL;

-- Queue 3: Stage 3 -> Stage 4 (Services that need heavy async enrichment)
CREATE TABLE queue_enrichments (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  service_id    BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL,
  attempts      INT NOT NULL DEFAULT 0,
  claimed_until BIGINT,
  queued_at     BIGINT NOT NULL,
  UNIQUE(service_id, kind)
);
CREATE INDEX idx_enrichments_unclaimed ON queue_enrichments(id) 
  WHERE claimed_until IS NULL;

-- =========================================================
-- 4. ASSETS (Screenshots, Favicons on disk)
-- =========================================================
CREATE TABLE service_assets (
  service_id BIGINT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,     -- 'favicon', 'screenshot'
  sha256     TEXT NOT NULL,
  taken_at   BIGINT NOT NULL,
  PRIMARY KEY (service_id, kind)
);

-- =========================================================
-- 5. SCANNER STATE (Subnet leasing)
-- =========================================================
CREATE TABLE subnet_scans (
  subnet_pattern   CIDR NOT NULL,
  port             INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  last_scan        BIGINT,
  ips_found        INT,
  leased_by        TEXT,
  lease_expires_at BIGINT,
  UNIQUE(subnet_pattern, port)
);
```

---

## 5. Type System & Vocabulary

The Rust types are the absolute source of truth. They map 1:1 to Shodan's JSON structure.

```rust
#[derive(Serialize, Deserialize)]
pub struct ServiceData {
    pub kind: String,            // "http", "ssh", "ssl", "unknown"
    pub product: Option<String>,
    pub version: Option<String>,
    pub tags: Vec<String>,
    
    // Nested payload, exactly like Shodan
    pub http: Option<HttpData>,
    pub ssl: Option<SslData>,
    pub raw: Option<String>,      // SSH/FTP banners or raw bytes
}

#[derive(Serialize, Deserialize)]
pub struct HttpData {
    pub status: u16,
    pub title: Option<String>,
    pub body: Option<String>,     // Cleaned/stripped HTML (done in Rust)
    pub headers: BTreeMap<String, Vec<String>>,
    pub favicon_hash: Option<i64>,
}

#[derive(Serialize, Deserialize)]
pub struct SslData {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub self_signed: bool,
}
```

---

## 6. Queue & Concurrency Model

Shared semantics in `src/queue.rs`. Leases prevent duplicate work across parallel workers or crashed nodes.

```sql
-- Claim (atomic, skips locked rows):
WITH claimed AS (
  UPDATE queue_service_probes SET claimed_until = $now + $lease
  WHERE id IN (
    SELECT id FROM queue_service_probes
    WHERE claimed_until IS NULL OR claimed_until < $now
    ORDER BY id LIMIT $batch
    FOR UPDATE SKIP LOCKED
  ) RETURNING id, ip, port, attempts
) SELECT * FROM claimed;

-- Heartbeat: worker extends claimed_until after finishing EACH item.
-- Sweep: expired + attempts >= max  -> DELETE.
--        expired + attempts < max   -> claimed_until = NULL (requeue).
```

---

## 7. Probe Engine

The `scanerr probe` flow is sequential, simple, and relies on `reqwest` for HTTP.

```rust
// Probe flow (in probe/dispatch.rs)
1. Reverse DNS (spawn_blocking, 1s timeout) -> update hosts
2. TCP connect (5s timeout)
3. Try HTTP GET / over plain TCP (reqwest, body cap 64KB, redirect cap 3)
   -> Success: strip HTML tags in Rust, parse title/headers, build HttpData -> Protocol::Http
   -> Failure: try TLS handshake (tokio-rustls)
     -> Success: try HTTP GET / over TLS
       -> Success: build HttpData + SslData -> Protocol::Https
       -> Failure: extract SslData -> Protocol::Tls
     -> Failure: read raw bytes (capped)
       -> starts with "SSH-": parse -> Protocol::Ssh
       -> matches FTP greeting: parse -> Protocol::Ftp
       -> else: Protocol::Unknown
4. Call fingerprint::identify() which adds tags/product to the ServiceData struct.
5. Serialize ServiceData to JSON and upsert the services row.
6. Enqueue enabled enrichers (e.g., favicon) if HTTP/HTTPS.
```

**Key decisions:**
*   **HTTP:** Use `reqwest` configured with `redirect_policy::limited(3)`, body cap, and a custom `User-Agent`. No hand-rolled parsers.
*   **TLS:** `tokio-rustls` with a custom `ServerCertVerifier` that accepts anything. ALPN offered as `["http/1.1"]`.
*   **GeoIP:** `maxminddb` crate. Updates `hosts` table on probe.

---

## 8. Fingerprinting & Signatures

Moved to the kernel (`src/fingerprint.rs`) because both `probe` and `enrich` need it.

```rust
/// Modifies the ServiceData struct in-place to add tags/product
pub fn identify(data: &mut ServiceData) { ... }
```

*   Built-in signatures embedded via `include_str!`. User overlay loaded from file.
*   Matchers: `title`, `header.server`, `favicon_hash`, `body` (string contains).
*   Enricher re-runs `identify()` after fetching a favicon and updates the JSONB `data` payload.

---

## 9. Enrichment Framework

Kept as a separate role because future enrichers (Chromium screenshots, RTSP frame grabs) are heavy and belong on dedicated nodes.

```rust
pub enum EnricherKind { Favicon } // Future: Screenshot, RtspFrame

impl EnricherKind {
    pub fn applies_to(&self) -> &[&str] {
        match self { EnricherKind::Favicon => &["http", "https"] }
    }
    pub async fn run(&self, svc: &ServiceRow, ctx: &EnrichCtx) -> Result<Asset, EnrichError>;
}
```

*   Claims from `queue_enrichments`.
*   Favicon: GET `/favicon.ico`, save to `assets_dir/<sha256>.ico`, insert into `service_assets`, extract `mmh3_32_signed(base64_strict_encode(bytes))`, update the JSONB `data.http.favicon_hash`, re-run fingerprint.

---

## 10. Query Language

Because we use pure JSONB, the query engine simply translates user input into JSONB containment operators.

*   `http.title:"Proxmox VE"` → `WHERE data @> '{"http": {"title": "Proxmox VE"}}'`
*   `tag:iot` → `WHERE data->'tags' ? 'iot'`
*   `favicon:-1234567890` → `WHERE data @> '{"http": {"favicon_hash": -1234567890}}'`
*   `ssl.cert_cn:"bank.com"` → `WHERE data @> '{"ssl": {"subject_cn": "bank.com"}}'`
*   `port:443` → `WHERE port = 443`
*   `country:DE` → `JOIN hosts ON ... WHERE country_code = 'DE'`

---

## 11. Configuration (`scanerr.toml`)

```toml
[database]
url = "postgres://scanerr:pass@localhost/scanerr"

[scanner]
# Stage 1: Broad discovery (find alive hosts)
discovery_ports = [22, 80, 443]
discovery_rate = 10000             # Fast rate for broad sweeps

# Stage 2: Deep scan (find all ports on alive hosts)
deep_scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1723, 3306, 3389, 5432, 6379, 8080, 8443]
deep_scan_rate = 500               # Slower, safer rate for single IPs

# Backpressure (Probe queue depth)
max_probe_queue_depth = 50000

ranges = ["10.0.0.0/8"]
random_scan = false
random_exclude_private = true

[probe]
concurrency = 128
timeout_secs = 5
user_agent = "scanerr/0.1 (personal scanner)"
geoip_db_path = "./GeoLite2-City.mmdb"

[enrich]
enabled = ["favicon"]
concurrency = 8

[storage]
assets_dir = "./assets"

[webui]
bind = "127.0.0.1:8080"

[signatures]
overlay_file = ""
disable = []
```

---

## 12. Implementation Phases

| Phase | Scope |
|---|---|
| **1 Foundation** | Types, config, db schema (with JSONB GIN indexes/leases), `queue.rs` families for all 3 queues. |
| **2 Discovery** | Subnet leasing, Stage 1 broad sweeper, Stage 2 deep scanner, backpressure gate, `scanerr scan`. |
| **3 Probes** | `reqwest` integration, sequential probe flow, GeoIP, Reverse DNS, `ServiceData` JSONB upserts, `scanerr probe`. |
| **4 Fingerprinting** | `Corpus` in kernel, built-in signatures, JSONB mutation. |
| **5 Enrichment** | `scanerr enrich` daemon, favicon grabber, mmh3 hashing, `service_assets` table, re-classification. |
| **6 Query & API** | JSONB containment query builder, webui routes, embedded templates. |
| **7 Polish** | `scanerr all` mode, docker-compose, README. |

---

## 13. Verification Gates

*   **Config:** `deny_unknown_fields` typos fail fast.
*   **Queue:** `claim`/`heartbeat`/`sweep` tests against local Postgres. No `COUNT(*)` for backpressure.
*   **Probes:** In-process tokio mock listeners (SSH/HTTP/TLS). Tests assert JSONB `data` shape.
*   **Masscan:** FAKE masscan script on PATH tests Command building and JSON parsing for both stages.
*   **Favicon:** Unit test verifying `mmh3_32_signed(base64(bytes))` matches known Shodan hash.
