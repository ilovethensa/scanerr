pub mod routes;
pub mod state;

use axum::{routing::get, Router};
use sqlx::PgPool;

pub fn create_router(pool: PgPool, tera: tera::Tera) -> Router {
    Router::new()
        .route("/", get(routes::index))
        .route("/search", get(routes::search))
        .route("/service/:id", get(routes::service_detail))
        .route("/api/search", get(routes::api_search))
        .route("/api/service/:id", get(routes::api_service))
        .with_state(state::AppState { pool, tera })
}
