use sqlx::PgPool;
use tera::Tera;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub tera: Tera,
}
