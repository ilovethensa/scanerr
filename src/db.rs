use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn connect(url: &str) -> Result<PgPool> {
    let max_conn: u32 = std::env::var("SCANERR_MAX_CONN")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let pool = PgPoolOptions::new()
        .max_connections(max_conn)
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    Ok(())
}
