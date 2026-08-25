use anyhow::Result;
use sqlx::PgPool;

use crate::models::ServiceData;
use super::{geoip, http, rndns, tls, raw};

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
    user_agent: &str,
    geoip_db: Option<&str>,
) -> Result<ProbeResult> {
    // Step 1: Ensure host exists (strip CIDR mask from ip::text)
    let clean_ip = ip_str.split('/').next().unwrap_or(ip_str);
    let host_id = ensure_host(pool, clean_ip).await?;

    // Step 2: Reverse DNS
    let rndns_result = rndns::resolve(clean_ip).await.unwrap_or(None);
    if let Some(ref hostname) = rndns_result {
        sqlx::query("UPDATE hosts SET reverse_dns = $1, last_seen = $2 WHERE id = $3")
            .bind(hostname)
            .bind(now())
            .bind(host_id)
            .execute(pool)
            .await?;
    }

    // Step 3: GeoIP lookup
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

    // Step 4: Try HTTP first, then TLS, then raw
    let data = if let Ok(d) = try_http(clean_ip, port, false, user_agent).await {
        d
    } else if let Ok(d) = try_http(clean_ip, port, true, user_agent).await {
        d
    } else if let Ok(d) = try_tls_then_raw(clean_ip, port, user_agent).await {
        d
    } else if let Ok(d) = try_raw(clean_ip, port).await {
        d
    } else {
        ServiceData::default()
    };

    let sni = None;

    Ok(ProbeResult {
        host_id,
        ip: clean_ip.to_string(),
        port,
        transport: transport.to_string(),
        sni,
        data,
    })
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

async fn try_http(
    ip: &str,
    port: u16,
    tls: bool,
    user_agent: &str,
) -> Result<ServiceData> {
    let http_data = http::probe_http(ip, port, tls, user_agent).await?;

    let mut data = ServiceData::default();
    data.kind = if tls { "https" } else { "http" }.into();
    data.http = Some(http_data);
    data.tags.push(if tls { "https" } else { "http" }.into());

    Ok(data)
}

async fn try_tls_then_raw(
    ip: &str,
    port: u16,
    _user_agent: &str,
) -> Result<ServiceData> {
    let (_tls_stream, ssl_data) = tls::tls_connect(ip, port).await?;

    let mut data = ServiceData::default();
    data.ssl = Some(ssl_data);
    data.kind = "tls".into();
    data.tags.push("tls".into());

    Ok(data)
}

async fn try_raw(ip: &str, port: u16) -> Result<ServiceData> {
    raw::read_raw_banner(
        ip,
        port,
        std::time::Duration::from_secs(5),
    )
    .await
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn upsert_service(pool: &PgPool, result: &ProbeResult) -> Result<i64> {
    let t = now();
    let data_json = serde_json::to_value(&result.data)?;

    let row: (i64,) = sqlx::query_as(
        "INSERT INTO services (host_id, port, transport, sni, data, first_seen, last_seen)
         VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (host_id, port, transport, sni)
         DO UPDATE SET data = $5, last_seen = $6
         RETURNING id",
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
    Ok(())
}

/// Probe a target without any DB operations — just returns the detected ServiceData.
pub async fn probe_standalone(
    ip_str: &str,
    port: u16,
    user_agent: &str,
) -> Result<ServiceData> {
    let clean_ip = ip_str.split('/').next().unwrap_or(ip_str);

    if let Ok(d) = try_http(clean_ip, port, false, user_agent).await {
        return Ok(d);
    }
    if let Ok(d) = try_http(clean_ip, port, true, user_agent).await {
        return Ok(d);
    }
    if let Ok(d) = try_tls_then_raw(clean_ip, port, user_agent).await {
        return Ok(d);
    }
    if let Ok(d) = try_raw(clean_ip, port).await {
        return Ok(d);
    }
    Ok(ServiceData::default())
}
