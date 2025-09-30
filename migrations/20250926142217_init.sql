CREATE TABLE ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    hostname TEXT,
    version_name TEXT,
    version_protocol INTEGER,
    players_online INTEGER,
    players_max INTEGER,
    description TEXT,
    gamemode TEXT,
    software TEXT,
    plugins TEXT,
    mods TEXT,
    favicon TEXT,
    raw_data TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uuid TEXT NOT NULL UNIQUE,
    servers TEXT, -- JSON array of IP addresses
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Table to track subnet scans and their results
CREATE TABLE IF NOT EXISTS subnet_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet_pattern TEXT UNIQUE NOT NULL,  -- e.g. "123.45.%"
    last_scan INTEGER NOT NULL,           -- UNIX timestamp
    ips_found INTEGER NOT NULL DEFAULT 0 -- number of new IPs found
);

-- Index to speed up subnet lookups
CREATE INDEX IF NOT EXISTS idx_subnet_pattern
ON subnet_scans(subnet_pattern);

CREATE TABLE IF NOT EXISTS migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    migration TEXT NOT NULL,
    applied_at INTEGER DEFAULT (strftime('%s','now'))
);