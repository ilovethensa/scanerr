use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Protocol Identity ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
    Ssh,
    Tls,
    Ftp,
    Smtp,
    Imap,
    Pop3,
    Telnet,
    Mqtt,
    Mysql,
    Redis,
    Pptp,
    Sccp,
    Mikrotik,
    Rtsp,
    Bgp,
    Hikvision,
    Unknown,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Ssh => "ssh",
            Protocol::Tls => "tls",
            Protocol::Ftp => "ftp",
            Protocol::Smtp => "smtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::Telnet => "telnet",
            Protocol::Mqtt => "mqtt",
            Protocol::Mysql => "mysql",
            Protocol::Redis => "redis",
            Protocol::Pptp => "pptp",
            Protocol::Sccp => "sccp",
            Protocol::Mikrotik => "mikrotik",
            Protocol::Rtsp => "rtsp",
            Protocol::Bgp => "bgp",
            Protocol::Hikvision => "hikvision",
            Protocol::Unknown => "unknown",
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Unknown
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Protocol {
    fn from(s: &str) -> Self {
        match s {
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "ssh" => Protocol::Ssh,
            "tls" => Protocol::Tls,
            "ftp" => Protocol::Ftp,
            "smtp" => Protocol::Smtp,
            "imap" => Protocol::Imap,
            "pop3" => Protocol::Pop3,
            "mqtt" => Protocol::Mqtt,
            "mysql" => Protocol::Mysql,
            "redis" => Protocol::Redis,
            "pptp" => Protocol::Pptp,
            "sccp" => Protocol::Sccp,
            "mikrotik" => Protocol::Mikrotik,
            "rtsp" => Protocol::Rtsp,
            _ => Protocol::Unknown,
        }
    }
}

// ─── ServiceData (Top-level JSONB shape) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceData {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl: Option<SslData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftp: Option<FtpData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<SmtpData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mqtt: Option<MqttData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sccp: Option<SccpData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mikrotik: Option<MikrotikData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtsp: Option<RtspData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<Pop3Data>,
}

// ─── Protocol Payloads ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpData {
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub headers: BTreeMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon_hash: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_hash: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers_hash: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub robots: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub securitytxt: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    pub self_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshData {
    pub raw: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymous_listing: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ehlo: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_code: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SccpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_interval: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MikrotikData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtspData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pop3Data {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub capabilities: Vec<String>,
}

// ─── Row types for DB ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostRow {
    pub id: i64,
    pub ip: IpAddr,
    pub reverse_dns: Option<String>,
    pub country_code: Option<String>,
    pub asn: Option<i32>,
    pub org: Option<String>,
    pub hostnames: Option<Vec<String>>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServiceRow {
    pub id: i64,
    pub host_id: i64,
    pub port: i32,
    pub transport: String,
    pub sni: Option<String>,
    pub data: serde_json::Value,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueueHostScan {
    pub id: i64,
    pub ip: IpAddr,
    pub attempts: i32,
    pub claimed_until: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueueServiceProbe {
    pub id: i64,
    pub ip: IpAddr,
    pub port: i32,
    pub transport: String,
    pub attempts: i32,
    pub claimed_until: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct QueueEnrichment {
    pub id: i64,
    pub service_id: i64,
    pub kind: String,
    pub attempts: i32,
    pub claimed_until: Option<i64>,
    pub queued_at: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServiceAsset {
    pub service_id: i64,
    pub kind: String,
    pub sha256: String,
    pub taken_at: i64,
}

// ─── Defaults ─────────────────────────────────────────────────────────────────

impl Default for ServiceData {
    fn default() -> Self {
        Self {
            kind: "unknown".into(),
            port: None,
            product: None,
            version: None,
            confidence: None,
            tags: Vec::new(),
            banner: None,
            http: None,
            ssl: None,
            ssh: None,
            ftp: None,
            smtp: None,
            mqtt: None,
            sccp: None,
            mikrotik: None,
            rtsp: None,
            pop3: None,
        }
    }
}
