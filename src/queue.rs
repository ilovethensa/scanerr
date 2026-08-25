use anyhow::Result;
use sqlx::PgPool;

pub struct LeasedQueue {
    table: &'static str,
}

impl LeasedQueue {
    pub fn new(table: &'static str) -> Self {
        Self { table }
    }

    pub async fn claim_host_scans(
        &self,
        pool: &PgPool,
        batch: i64,
        now: i64,
    ) -> Result<Vec<(i64, String)>> {
        let rows = sqlx::query_as::<_, (i64, String)>(
            r#"
            WITH claimed AS (
              UPDATE queue_host_scans SET claimed_until = $1
              WHERE id IN (
                SELECT id FROM queue_host_scans
                WHERE claimed_until IS NULL OR claimed_until < $2
                ORDER BY id LIMIT $3
                FOR UPDATE SKIP LOCKED
              ) RETURNING id, ip::text
            ) SELECT * FROM claimed;
            "#,
        )
        .bind(now + 300)
        .bind(now)
        .bind(batch)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn claim_service_probes(
        &self,
        pool: &PgPool,
        batch: i64,
        now: i64,
    ) -> Result<Vec<(i64, String, i32, String)>> {
        let rows = sqlx::query_as::<_, (i64, String, i32, String)>(
            r#"
            WITH claimed AS (
              UPDATE queue_service_probes SET claimed_until = $1
              WHERE id IN (
                SELECT id FROM queue_service_probes
                WHERE claimed_until IS NULL OR claimed_until < $2
                ORDER BY id LIMIT $3
                FOR UPDATE SKIP LOCKED
              ) RETURNING id, ip::text, port, transport
            ) SELECT * FROM claimed;
            "#,
        )
        .bind(now + 300)
        .bind(now)
        .bind(batch)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn claim_enrichments(
        &self,
        pool: &PgPool,
        batch: i64,
        now: i64,
    ) -> Result<Vec<(i64, i64, String)>> {
        let rows = sqlx::query_as::<_, (i64, i64, String)>(
            r#"
            WITH claimed AS (
              UPDATE queue_enrichments SET claimed_until = $1
              WHERE id IN (
                SELECT id FROM queue_enrichments
                WHERE claimed_until IS NULL OR claimed_until < $2
                ORDER BY id LIMIT $3
                FOR UPDATE SKIP LOCKED
              ) RETURNING id, service_id, kind
            ) SELECT * FROM claimed;
            "#,
        )
        .bind(now + 300)
        .bind(now)
        .bind(batch)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    pub async fn heartbeat(&self, pool: &PgPool, id: i64, now: i64) -> Result<()> {
        let q = format!(
            "UPDATE {} SET claimed_until = $1 WHERE id = $2",
            self.table
        );
        sqlx::query(&q)
            .bind(now + 300)
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn sweep(&self, pool: &PgPool, max_attempts: i32, now: i64) -> Result<u64> {
        let requeue = format!(
            "UPDATE {t} SET claimed_until = NULL WHERE (claimed_until IS NOT NULL AND claimed_until < $1) AND attempts < $2",
            t = self.table
        );
        sqlx::query(&requeue)
            .bind(now)
            .bind(max_attempts)
            .execute(pool)
            .await?
            .rows_affected();

        let delete = format!(
            "DELETE FROM {t} WHERE (claimed_until IS NOT NULL AND claimed_until < $1) AND attempts >= $2",
            t = self.table
        );
        let deleted = sqlx::query(&delete)
            .bind(now)
            .bind(max_attempts)
            .execute(pool)
            .await?
            .rows_affected();

        Ok(deleted)
    }

    pub async fn increment_attempts(&self, pool: &PgPool, id: i64) -> Result<()> {
        let q = format!("UPDATE {} SET attempts = attempts + 1 WHERE id = $1", self.table);
        sqlx::query(&q).bind(id).execute(pool).await?;
        Ok(())
    }
}

pub async fn backpressure_active(pool: &PgPool, max_depth: u32) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM queue_service_probes WHERE claimed_until IS NULL",
    )
    .fetch_one(pool)
    .await?;

    Ok(count.0 >= max_depth as i64)
}

pub async fn insert_host_scan(pool: &PgPool, ip: &str) -> Result<()> {
    sqlx::query("INSERT INTO queue_host_scans (ip) VALUES ($1::inet) ON CONFLICT (ip) DO NOTHING")
        .bind(ip)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn insert_service_probe(
    pool: &PgPool,
    ip: &str,
    port: i32,
    transport: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO queue_service_probes (ip, port, transport) VALUES ($1::inet, $2, $3) ON CONFLICT (ip, port, transport) DO NOTHING",
    )
    .bind(ip)
    .bind(port)
    .bind(transport)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_enrichment(pool: &PgPool, service_id: i64, kind: &str, now: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO queue_enrichments (service_id, kind, queued_at) VALUES ($1, $2, $3) ON CONFLICT (service_id, kind) DO NOTHING",
    )
    .bind(service_id)
    .bind(kind)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}
