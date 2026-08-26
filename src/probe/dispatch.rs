use anyhow::Result;
use sqlx::PgPool;

use crate::fingerprint::Engine;
use crate::models::ServiceData;
use super::{engine, geoip, rndns};

#[derive(Debug)]
pub struct ProbeResult {
    pub host_id: i64,
    pub ip: String,
    pub port: u16,
    pub transport: String,
    pub sni: Option<String>,
    pub data: ServiceData,
}

pub async fn probe(
    pool: &PgPool,
    ip_str: &str,
    port: u16,
    transport: &str,
    _user_agent: &str,
    geoip_db: Option<&str>,
    engine: &Engine,
) -> Result<ProbeResult> {
    let clean_ip = ip_str.split('/').next().unwrap_or(ip_str);

    let registry = engine::ProbeRegistry::new();
    let mut data = match registry.dispatch(clean_ip, port, _user_agent).await {
        Ok(d) => d,
        Err(e) => {
            anyhow::bail!("probe dispatch failed for {}:{}: {}", clean_ip, port, e);
        }
    };
    data.port = Some(port);

    engine.identify(&mut data);

    // Only create/update the host after a successful probe
    let host_id = ensure_host(pool, clean_ip).await?;

    let rndns_result = rndns::resolve(clean_ip).await.unwrap_or(None);
    if let Some(ref hostname) = rndns_result {
        sqlx::query("UPDATE hosts SET reverse_dns = $1, last_seen = $2 WHERE id = $3")
            .bind(hostname)
            .bind(now())
            .bind(host_id)
            .execute(pool)
            .await?;
    }

    if let Some(db_path) = geoip_db {
        if let Ok(info) = geoip::lookup(clean_ip, db_path) {
            sqlx::query(
                "UPDATE hosts SET country_code = COALESCE($1, country_code), last_seen = $2 WHERE id = $3",
            )
            .bind(&info.country_code)
            .bind(now())
            .bind(host_id)
            .execute(pool)
            .await?;
        }
    }

    Ok(ProbeResult {
        host_id,
        ip: clean_ip.to_string(),
        port,
        transport: transport.to_string(),
        sni: None,
        data,
    })
}

/// Probe a target without any DB operations.
pub async fn probe_standalone(
    ip_str: &str,
    port: u16,
    user_agent: &str,
    engine: &Engine,
) -> Result<ServiceData> {
    let clean_ip = ip_str.split('/').next().unwrap_or(ip_str);
    let registry = engine::ProbeRegistry::new();
    let mut data = registry.dispatch(clean_ip, port, user_agent).await?;
    data.port = Some(port);
    engine.identify(&mut data);
    Ok(data)
}

async fn ensure_host(pool: &PgPool, ip: &str) -> Result<i64> {
    let now = now();
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO hosts (ip, first_seen, last_seen) VALUES ($1::inet, $2, $2)
         ON CONFLICT (ip) DO UPDATE SET last_seen = $2
         RETURNING id",
    )
    .bind(ip)
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn upsert_service(pool: &PgPool, result: &ProbeResult) -> Result<i64> {
    let t = now();
    let data_json = sanitize_json_nulls(serde_json::to_value(&result.data)?);

    let row: (i64,) = sqlx::query_as(
        "WITH existing AS (
            SELECT id FROM services
            WHERE host_id = $1 AND port = $2 AND transport = $3
            AND (sni = $4 OR (sni IS NULL AND $4 IS NULL))
            LIMIT 1
         ),
         upd AS (
            UPDATE services SET data = $5, last_seen = $6
            WHERE id = (SELECT id FROM existing)
            RETURNING id
         ),
         ins AS (
            INSERT INTO services (host_id, port, transport, sni, data, first_seen, last_seen)
            SELECT $1, $2, $3, $4, $5, $6, $6
            WHERE NOT EXISTS (SELECT 1 FROM existing)
            RETURNING id
         )
         SELECT id FROM upd
         UNION ALL
         SELECT id FROM ins",
    )
    .bind(result.host_id)
    .bind(result.port as i32)
    .bind(&result.transport)
    .bind(&result.sni)
    .bind(&data_json)
    .bind(t)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn maybe_enqueue_enrichments(
    pool: &PgPool,
    service_id: i64,
    data: &ServiceData,
) -> Result<()> {
    if data.http.is_some() {
        crate::queue::insert_enrichment(pool, service_id, "favicon", now()).await?;
    }
    if data.rtsp.is_some() {
        crate::queue::insert_enrichment(pool, service_id, "rtsp_frame", now()).await?;
    }
    Ok(())
}

fn sanitize_json_nulls(val: serde_json::Value) -> serde_json::Value {
    match val {
        serde_json::Value::String(s) => {
            serde_json::Value::String(s.replace('\0', ""))
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(sanitize_json_nulls).collect())
        }
        serde_json::Value::Object(map) => {
            serde_json::Value::Object(map.into_iter().map(|(k, v)| (k, sanitize_json_nulls(v))).collect())
        }
        other => other,
    }
}
