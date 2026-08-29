use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::state::AppState;
use crate::query::{parse_query, build_search_query};

fn html_response(body: String) -> (StatusCode, HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html; charset=utf-8"));
    (StatusCode::OK, headers, body)
}

pub async fn index(State(state): State<AppState>) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let sql = "SELECT h.id, host(h.ip) as ip, h.reverse_dns, h.country_code, h.asn, h.org, \
               h.first_seen, h.last_seen, \
               (SELECT count(*)::int FROM services WHERE host_id = h.id) as service_count, \
               COALESCE(( \
                   SELECT array_agg(DISTINCT t) FROM \
                   services s, jsonb_array_elements_text(s.data->'tags') t \
                   WHERE s.host_id = h.id \
               ), ARRAY[]::text[]) as tags, \
               COALESCE(( \
                   SELECT jsonb_agg(jsonb_build_object( \
                       'port', s.port, \
                       'service', s.data->>'kind', \
                       'product', s.data->>'product', \
                       'title', s.data->'http'->>'title', \
                       'tags', COALESCE(( \
                           SELECT array_agg(DISTINCT tt) FROM \
                           jsonb_array_elements_text(s.data->'tags') tt \
                       ), ARRAY[]::text[]) \
                   ) ORDER BY s.port) \
                   FROM services s WHERE s.host_id = h.id \
               ), '[]'::jsonb) as services \
               FROM hosts h WHERE NOT h.is_honeypot ORDER BY h.last_seen DESC LIMIT 50";

    let mut hosts: Vec<HostSummary> = sqlx::query_as(sql)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("index query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Group services by product/title in Rust
    for h in &mut hosts {
        h.service_groups = group_services(&h.services);
    }

    let mut ctx = tera::Context::new();
    ctx.insert("title", "scanerr - Service Scanner");
    ctx.insert("hosts", &hosts);

    let body = state
        .tera
        .render("index.html", &ctx)
        .map_err(|e| {
            tracing::error!("index render failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(html_response(body))
}

pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let query = params.get("q").cloned().unwrap_or_default();
    let ast = parse_query(&query);
    let (sql, query_params) = build_search_query(&ast);

    let rows = fetch_service_rows(&state.pool, &sql, &query_params)
        .await
        .map_err(|e| {
            tracing::error!("search query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut services_json: Vec<Value> = Vec::new();
    for (id, port, transport, sni, data, first_seen, last_seen, ip, country, asn, org) in &rows {
        services_json.push(json!({
            "id": id,
            "port": port,
            "transport": transport,
            "sni": sni,
            "data": data,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "ip": ip,
            "country": country,
            "asn": asn,
            "org": org,
        }));
    }

    let mut ctx = tera::Context::new();
    ctx.insert("query", &query);
    ctx.insert("results", &rows.len());
    ctx.insert("services", &services_json);

    let body = state
        .tera
        .render("search.html", &ctx)
        .map_err(|e| {
            tracing::error!("search render failed: {} {:?}", e, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(html_response(body))
}

pub async fn service_detail(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let sql = "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
               host(h.ip), h.country_code, h.asn, h.org \
               FROM services s JOIN hosts h ON s.host_id = h.id WHERE s.id = $1::bigint";

    let rows = fetch_service_rows(&state.pool, sql, &[id.to_string()])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match rows.into_iter().next() {
        Some(row) => {
            let mut ctx = tera::Context::new();
            ctx.insert("service", &row);
            let body = state
                .tera
                .render("service.html", &ctx)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(html_response(body))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn host_detail(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let host_sql = "SELECT h.id, host(h.ip) as ip, h.reverse_dns, h.country_code, h.asn, h.org, \
                    h.first_seen, h.last_seen, \
                    (SELECT count(*)::int FROM services WHERE host_id = h.id) as service_count \
                    FROM hosts h WHERE host(h.ip) = $1 LIMIT 1";

    let hosts: Vec<HostSummary> = sqlx::query_as(host_sql)
        .bind(&ip)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("host query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let host = match hosts.into_iter().next() {
        Some(h) => h,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let svc_sql = "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
                   host(h.ip), h.country_code, h.asn, h.org \
                   FROM services s JOIN hosts h ON s.host_id = h.id \
                   WHERE h.id = $1::bigint ORDER BY s.port";

    let services = fetch_service_rows(&state.pool, svc_sql, &[host.id.to_string()])
        .await
        .map_err(|e| {
            tracing::error!("host services query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let mut services_json: Vec<Value> = Vec::new();
    for (id, port, transport, sni, data, first_seen, last_seen, ip, country, asn, org) in &services {
        services_json.push(json!({
            "id": id,
            "port": port,
            "transport": transport,
            "sni": sni,
            "data": data,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "ip": ip,
            "country": country,
            "asn": asn,
            "org": org,
        }));
    }

    let mut ctx = tera::Context::new();
    ctx.insert("host", &host);
    ctx.insert("services", &services_json);

    let body = state
        .tera
        .render("host.html", &ctx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(html_response(body))
}

pub async fn api_host(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let host_sql = "SELECT h.id, host(h.ip), h.reverse_dns, h.country_code, h.asn, h.org, \
                    h.first_seen, h.last_seen, \
                    (SELECT count(*)::int FROM services WHERE host_id = h.id) as service_count \
                    FROM hosts h WHERE host(h.ip) = $1 LIMIT 1";

    let hosts: Vec<HostSummary> = sqlx::query_as(host_sql)
        .bind(&ip)
        .fetch_all(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let host = match hosts.into_iter().next() {
        Some(h) => h,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let svc_sql = "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
                   host(h.ip), h.country_code, h.asn, h.org \
                   FROM services s JOIN hosts h ON s.host_id = h.id \
                   WHERE h.id = $1::bigint ORDER BY s.port";

    let services = fetch_service_rows(&state.pool, svc_sql, &[host.id.to_string()])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let svc_json: Vec<Value> = services
        .into_iter()
        .map(|(id, port, transport, sni, data, first_seen, last_seen, ip, country, asn, org)| {
            json!({
                "id": id, "port": port, "transport": transport, "sni": sni,
                "data": data, "first_seen": first_seen, "last_seen": last_seen,
                "ip": ip, "country": country, "asn": asn, "org": org,
            })
        })
        .collect();

    Ok(Json(json!({ "host": host, "services": svc_json })))
}

pub async fn api_search(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let query = params.get("q").cloned().unwrap_or_default();
    let ast = parse_query(&query);
    let (sql, query_params) = build_search_query(&ast);

    let rows = fetch_service_rows(&state.pool, &sql, &query_params)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let results: Vec<Value> = rows
        .into_iter()
        .map(|(id, port, transport, sni, data, first_seen, last_seen, ip, country, asn, org)| {
            json!({
                "id": id,
                "port": port,
                "transport": transport,
                "sni": sni,
                "data": data,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "ip": ip,
                "country": country,
                "asn": asn,
                "org": org,
            })
        })
        .collect();

    Ok(Json(json!({
        "results": results,
        "total": results.len(),
    })))
}

pub async fn api_service(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, StatusCode> {
    let sql = "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
               host(h.ip), h.country_code, h.asn, h.org \
               FROM services s JOIN hosts h ON s.host_id = h.id WHERE s.id = $1::bigint";

    let rows = fetch_service_rows(&state.pool, sql, &[id.to_string()])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match rows.into_iter().next() {
        Some((id, port, transport, sni, data, first_seen, last_seen, ip, country, asn, org)) => {
            Ok(Json(json!({
                "id": id,
                "port": port,
                "transport": transport,
                "sni": sni,
                "data": data,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "ip": ip,
                "country": country,
                "asn": asn,
                "org": org,
            })))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct PortStat {
    port: i32,
    count: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct KindStat {
    kind: String,
    count: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct CountryStat {
    country: String,
    count: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct ProductStat {
    product: String,
    count: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct TransportStat {
    transport: String,
    count: i64,
}

#[derive(Debug, sqlx::FromRow, serde::Serialize)]
struct TagStat {
    tag: String,
    count: i64,
}

#[derive(serde::Serialize)]
struct QueueStat {
    queue: String,
    total: i64,
    unclaimed: i64,
}

#[derive(serde::Serialize)]
struct StatsData {
    total_hosts: i64,
    total_services: i64,
    total_countries: i64,
    ports: Vec<PortStat>,
    kinds: Vec<KindStat>,
    products: Vec<ProductStat>,
    transports: Vec<TransportStat>,
    tags: Vec<TagStat>,
    countries: Vec<CountryStat>,
    queues: Vec<QueueStat>,
}

pub async fn stats(
    State(state): State<AppState>,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let pool = &state.pool;

    let total_hosts: (i64,) = sqlx::query_as("SELECT count(*) FROM hosts WHERE NOT is_honeypot")
        .fetch_one(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total_services: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM services s JOIN hosts h ON s.host_id = h.id WHERE NOT h.is_honeypot")
        .fetch_one(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total_countries: (i64,) = sqlx::query_as(
        "SELECT count(DISTINCT country_code) FROM hosts WHERE country_code IS NOT NULL AND NOT is_honeypot")
        .fetch_one(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let ports: Vec<PortStat> = sqlx::query_as(
        "SELECT s.port as port, count(*) as count FROM services s \
         JOIN hosts h ON s.host_id = h.id WHERE NOT h.is_honeypot \
         GROUP BY s.port ORDER BY count DESC LIMIT 20"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let kinds: Vec<KindStat> = sqlx::query_as(
        "SELECT s.data->>'kind' as kind, count(*) as count FROM services s \
         JOIN hosts h ON s.host_id = h.id WHERE NOT h.is_honeypot \
         GROUP BY s.data->>'kind' ORDER BY count DESC LIMIT 15"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let countries: Vec<CountryStat> = sqlx::query_as(
        "SELECT COALESCE(h.country_code, '??') as country, count(*) as count \
         FROM hosts h WHERE NOT h.is_honeypot GROUP BY h.country_code ORDER BY count DESC LIMIT 15"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let products: Vec<ProductStat> = sqlx::query_as(
        "SELECT s.data->>'product' as product, count(*) as count FROM services s \
         JOIN hosts h ON s.host_id = h.id WHERE NOT h.is_honeypot \
         AND s.data->>'product' IS NOT NULL \
         GROUP BY s.data->>'product' ORDER BY count DESC LIMIT 20"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let transports: Vec<TransportStat> = sqlx::query_as(
        "SELECT s.transport as transport, count(*) as count FROM services s \
         JOIN hosts h ON s.host_id = h.id WHERE NOT h.is_honeypot \
         GROUP BY s.transport ORDER BY count DESC"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let tags: Vec<TagStat> = sqlx::query_as(
        "SELECT t as tag, count(*) as count FROM services s \
         JOIN hosts h ON s.host_id = h.id, jsonb_array_elements_text(s.data->'tags') t \
         WHERE NOT h.is_honeypot GROUP BY t ORDER BY count DESC LIMIT 20"
    ).fetch_all(pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let queues = vec![
        QueueStat {
            queue: "host_scans".into(),
            total: sqlx::query_scalar::<_, i64>("SELECT count(*) FROM queue_host_scans")
                .fetch_one(pool).await.unwrap_or(0),
            unclaimed: sqlx::query_scalar::<_, i64>("SELECT count(*) FROM queue_host_scans WHERE claimed_until IS NULL")
                .fetch_one(pool).await.unwrap_or(0),
        },
        QueueStat {
            queue: "service_probes".into(),
            total: sqlx::query_scalar::<_, i64>("SELECT count(*) FROM queue_service_probes")
                .fetch_one(pool).await.unwrap_or(0),
            unclaimed: sqlx::query_scalar::<_, i64>("SELECT count(*) FROM queue_service_probes WHERE claimed_until IS NULL")
                .fetch_one(pool).await.unwrap_or(0),
        },
    ];

    let data = StatsData {
        total_hosts: total_hosts.0,
        total_services: total_services.0,
        total_countries: total_countries.0,
        ports,
        kinds,
        products,
        transports,
        tags,
        countries,
        queues,
    };

    let mut ctx = tera::Context::new();
    ctx.insert("title", "scanerr - Statistics");
    ctx.insert("stats", &data);

    let body = state.tera.render("stats.html", &ctx)
        .map_err(|e| {
            tracing::error!("stats render failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(html_response(body))
}

type ServiceRow = (i64, i32, String, Option<String>, Value, i64, i64, String, Option<String>, Option<i32>, Option<String>);

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct HostSummary {
    pub id: i64,
    pub ip: String,
    pub reverse_dns: Option<String>,
    pub country_code: Option<String>,
    pub asn: Option<i32>,
    pub org: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub service_count: Option<i32>,
    #[sqlx(default)]
    pub is_honeypot: bool,
    #[sqlx(default)]
    pub tags: Option<Vec<String>>,
    #[sqlx(default)]
    pub services: Option<serde_json::Value>,
    #[sqlx(skip)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub service_groups: Vec<ServiceGroup>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceGroup {
    pub ports: Vec<i32>,
    pub name: String,
}

fn group_services(services: &Option<serde_json::Value>) -> Vec<ServiceGroup> {
    let svcs = match services {
        Some(serde_json::Value::Array(arr)) => arr,
        _ => return Vec::new(),
    };

    let mut groups: std::collections::HashMap<String, Vec<i32>> = std::collections::HashMap::new();

    for svc in svcs {
        let port = svc.get("port").and_then(|p| p.as_i64()).unwrap_or(0) as i32;
        let name = svc.get("product")
            .or_else(|| svc.get("title"))
            .and_then(|v| v.as_str())
            .or_else(|| svc.get("service").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string();

        groups.entry(name).or_default().push(port);
    }

    let mut result: Vec<ServiceGroup> = groups.into_iter()
        .map(|(name, mut ports)| {
            ports.sort();
            ports.dedup();
            ServiceGroup { ports, name }
        })
        .collect();

    result.sort_by(|a, b| a.ports[0].cmp(&b.ports[0]));
    result
}

async fn fetch_service_rows(
    pool: &PgPool,
    sql: &str,
    params: &[String],
) -> Result<Vec<ServiceRow>, sqlx::Error> {
    let mut query = sqlx::query_as::<_, ServiceRow>(sql);
    for param in params {
        query = query.bind(param);
    }
    query.fetch_all(pool).await
}
