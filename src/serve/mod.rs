pub mod routes;
pub mod state;

use axum::{routing::get, Router};
use sqlx::PgPool;

pub fn create_router(pool: PgPool, tera: tera::Tera) -> Router {
    Router::new()
        .route("/", get(routes::index))
        .route("/search", get(routes::search))
        .route("/hosts/:ip", get(routes::host_detail))
        .route("/service/:id", get(routes::service_detail))
        .route("/stats", get(routes::stats))
        .route("/status", get(routes::stats))
        .route("/api/search", get(routes::api_search))
        .route("/api/host/:ip", get(routes::api_host))
        .route("/api/service/:id", get(routes::api_service))
        .with_state(state::AppState { pool, tera })
}
