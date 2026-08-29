use scanerr_fingerprint::Engine;
use crate::models::ServiceData;
use crate::normalize::normalize_service;

/// Re-run every HTTP service through the fingerprint engine so they get
/// re-identified against the current signature corpus.
///
/// One-off data maintenance command. Paginated by id (keyset) so it never
/// loads the whole table into memory and can be re-run safely. Only rows that
/// already carry an `http` payload are touched — re-identification works off
/// the stored headers/body, no network probing is performed.
pub async fn reidentify_http(pool: &sqlx::PgPool, engine: &Engine) -> anyhow::Result<()> {
    use sqlx::Row;

    const CHUNK: i64 = 1000;
    let mut last_id: i64 = 0;
    let mut updated = 0u32;
    let mut scanned = 0u32;

    loop {
        let pg_rows = sqlx::query(
            "SELECT id, data FROM services
             WHERE data->'http' IS NOT NULL AND id > $1
             ORDER BY id ASC LIMIT $2",
        )
        .bind(last_id)
        .bind(CHUNK)
        .fetch_all(pool)
        .await?;

        let rows: Vec<(i64, serde_json::Value)> = pg_rows
            .iter()
            .map(|row| (row.get::<i64, _>("id"), row.get::<serde_json::Value, _>("data")))
            .collect();

        if rows.is_empty() {
            break;
        }

        for (id, data_val) in &rows {
            scanned += 1;
            let mut data: ServiceData = serde_json::from_value(data_val.clone())?;

            // Reset fingerprint-derived fields so stale signature matches are
            // cleared before re-identification. Tech tags live in http.tags
            // (regenerated below); data.tags is rebuilt by normalize_service
            // from the kind category plus any signature tags we re-merge.
            data.product = None;
            data.version = None;
            data.confidence = None;
            data.tags.clear();

            // Re-run technology detection from the stored HTTP headers/body so
            // the result matches a fresh probe as closely as possible.
            if let Some(ref mut http) = data.http {
                let tech_tags = scanerr_fingerprint::tech::detect(
                    &http.headers,
                    http.body.as_deref().unwrap_or(""),
                );
                for tag in tech_tags {
                    if !http.tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                        http.tags.push(tag);
                    }
                }
            }

            engine.identify(&mut data);
            normalize_service(&mut data);

            let new_json = serde_json::to_value(&data)?;
            if *data_val != new_json {
                sqlx::query("UPDATE services SET data = $1 WHERE id = $2")
                    .bind(&new_json)
                    .bind(id)
                    .execute(pool)
                    .await?;
                updated += 1;
            }
        }

        last_id = rows.last().unwrap().0;

        tracing::info!(
            "reidentify: progress scanned={} updated={} last_id={}",
            scanned, updated, last_id
        );

        if (rows.len() as i64) < CHUNK {
            break;
        }
    }

    tracing::info!("reidentify: scanned {} http services, updated {}", scanned, updated);
    Ok(())
}
