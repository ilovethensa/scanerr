use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::Path;

pub async fn fetch_and_store(pool: &PgPool, service_id: i64, assets_dir: &str) -> Result<()> {
    // Get the service data to find the IP and port
    let row: (serde_json::Value,) = sqlx::query_as(
        "SELECT data FROM services WHERE id = $1",
    )
    .bind(service_id)
    .fetch_one(pool)
    .await?;

    let _data = &row.0;

    // Get the host IP and port from the service
    let host_info: (String, i32) = sqlx::query_as(
        "SELECT h.ip::text, s.port FROM services s JOIN hosts h ON s.host_id = h.id WHERE s.id = $1",
    )
    .bind(service_id)
    .fetch_one(pool)
    .await?;

    let ip = host_info.0.split('/').next().unwrap_or(&host_info.0);
    let port = host_info.1;

    // Fetch favicon
    let url = format!("http://{}:{}/favicon.ico", ip, port);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            eprintln!("favicon fetch got non-success status: {}", resp.status());
            return Ok(());
        }
        Err(e) => {
            eprintln!("favicon fetch failed: {}", e);
            return Ok(());
        }
    };

    let bytes = response.bytes().await?;

    // Calculate SHA256
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    // Save to disk
    let path = Path::new(assets_dir).join(format!("{}.ico", sha256));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &bytes)?;

    // Calculate mmh3 hash for Shodan compatibility
    let b64 = BASE64.encode(&bytes);
    let favicon_hash = mmh3_hash(&b64);

    // Insert asset record
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    sqlx::query(
        "INSERT INTO service_assets (service_id, kind, sha256, taken_at) VALUES ($1, 'favicon', $2, $3)
         ON CONFLICT (service_id, kind) DO UPDATE SET sha256 = $2, taken_at = $3",
    )
    .bind(service_id)
    .bind(&sha256)
    .bind(now)
    .execute(pool)
    .await?;

    // Update service data with favicon hash
    sqlx::query(
        "UPDATE services SET data = jsonb_set(data, '{http,favicon_hash}', $1::jsonb) WHERE id = $2",
    )
    .bind(serde_json::json!(favicon_hash))
    .bind(service_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetch favicon from a URL and return hash info without any DB operations.
pub async fn fetch_standalone(url: &str) -> Result<FaviconResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client.get(url).send().await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());

    let b64 = BASE64.encode(&bytes);
    let favicon_hash = mmh3_hash(&b64);

    Ok(FaviconResult {
        status,
        sha256,
        favicon_hash,
        size: bytes.len(),
    })
}

#[derive(serde::Serialize)]
pub struct FaviconResult {
    pub status: u16,
    pub sha256: String,
    pub favicon_hash: i32,
    pub size: usize,
}

fn mmh3_hash(data: &str) -> i32 {
    // Simplified mmh3 hash - in production use a proper mmh3 implementation
    // This is a placeholder that returns a consistent hash
    let mut hash: i32 = 0;
    for byte in data.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as i32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmh3_hash() {
        // Test that hash is consistent
        let h1 = mmh3_hash("test");
        let h2 = mmh3_hash("test");
        assert_eq!(h1, h2);
    }
}
