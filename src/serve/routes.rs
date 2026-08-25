use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    Json,
};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::state::AppState;
use crate::query::QueryBuilder;

fn html_response(body: String) -> (StatusCode, HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("text/html; charset=utf-8"));
    (StatusCode::OK, headers, body)
}

pub async fn index(State(state): State<AppState>) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let mut ctx = tera::Context::new();
    ctx.insert("title", "scanerr - Service Scanner");

    let body = state
        .tera
        .render("index.html", &ctx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(html_response(body))
}

pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, HeaderMap, String), StatusCode> {
    let query = params.get("q").cloned().unwrap_or_default();
    let terms = QueryBuilder::parse_filter(&query);

    let mut qb = QueryBuilder::new();
    for term in &terms {
        match term.key.as_str() {
            "port" => {
                if let Ok(port) = term.value.parse::<u16>() {
                    qb.add_port(port);
                }
            }
            "tag" => qb.add_tag(&term.value),
            "country" => qb.add_country(&term.value),
            "http.title" => qb.add_jsonb_condition("http.title", &term.value),
            "http.server" => qb.add_jsonb_condition("http.server", &term.value),
            "ssl.cert_cn" => qb.add_jsonb_condition("ssl.subject_cn", &term.value),
            _ => {}
        }
    }

    let sql = qb.build_query();
    let query_params = qb.params();

    let rows = fetch_service_rows(&state.pool, &sql, query_params)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut ctx = tera::Context::new();
    ctx.insert("query", &query);
    ctx.insert("results", &rows.len());
    ctx.insert("services", &rows);

    let body = state
        .tera
        .render("search.html", &ctx)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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

pub async fn api_search(
    State(state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let query = params.get("q").cloned().unwrap_or_default();
    let terms = QueryBuilder::parse_filter(&query);

    let mut qb = QueryBuilder::new();
    for term in &terms {
        match term.key.as_str() {
            "port" => {
                if let Ok(port) = term.value.parse::<u16>() {
                    qb.add_port(port);
                }
            }
            "tag" => qb.add_tag(&term.value),
            "country" => qb.add_country(&term.value),
            "http.title" => qb.add_jsonb_condition("http.title", &term.value),
            _ => {}
        }
    }

    let sql = qb.build_query();
    let query_params = qb.params();

    let rows = fetch_service_rows(&state.pool, &sql, query_params)
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

type ServiceRow = (i64, i32, String, Option<String>, Value, i64, i64, String, Option<String>, Option<i32>, Option<String>);

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
