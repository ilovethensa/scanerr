-- =========================================================
-- 1. HOSTS (The Machine Context)
-- =========================================================
CREATE TABLE hosts (
  id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip           INET UNIQUE NOT NULL,
  reverse_dns  TEXT,
  country_code TEXT,
  asn          INTEGER,
  org          TEXT,
  hostnames    TEXT[],
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
  sni        TEXT,
  data       JSONB NOT NULL,
  first_seen BIGINT NOT NULL,
  last_seen  BIGINT NOT NULL,
  UNIQUE(host_id, port, transport, sni)
);

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
  kind       TEXT NOT NULL,
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
