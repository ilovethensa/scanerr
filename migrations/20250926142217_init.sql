-- Add migration script here

CREATE TABLE ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    hostname TEXT,
    dns_a_records TEXT,
    dns_cname TEXT,
    version_name TEXT,
    version_protocol INTEGER,
    players_online INTEGER,
    players_max INTEGER,
    player_sample TEXT,
    description TEXT,
    gamemode TEXT,
    software TEXT,
    plugins TEXT,
    mods TEXT,
    favicon TEXT,
    raw_data TEXT
);

CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    uuid TEXT NOT NULL UNIQUE,
    ips TEXT -- JSON array of IP addresses
);
