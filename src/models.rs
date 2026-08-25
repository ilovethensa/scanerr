use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceData {
    pub kind: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub tags: Vec<String>,
    pub http: Option<HttpData>,
    pub ssl: Option<SslData>,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpData {
    pub status: u16,
    pub title: Option<String>,
    pub body: Option<String>,
    pub headers: BTreeMap<String, Vec<String>>,
    pub favicon_hash: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslData {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub self_signed: bool,
}


// -- Row types for DB --

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

impl Default for ServiceData {
    fn default() -> Self {
        Self {
            kind: "unknown".into(),
            product: None,
            version: None,
            tags: Vec::new(),
            http: None,
            ssl: None,
            raw: None,
        }
    }
}
