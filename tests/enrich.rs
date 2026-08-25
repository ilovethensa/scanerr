use scanerr::enrich::favicon;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[sqlx::test(migrations = "./migrations")]
async fn test_enrich_favicon(pool: sqlx::PgPool) {
    // Mock HTTP server serving a favicon
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf = [0u8; 2048];
        let _ = stream.read(&mut buf).await;

        // A minimal valid ICO (1x1 pixel)
        let favicon: &[u8] = &[
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x30, 0x00,
            0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: image/x-icon\r\nConnection: close\r\n\r\n",
            favicon.len()
        );
        stream.write_all(header.as_bytes()).await.ok();
        stream.write_all(favicon).await.ok();
    });

    // Insert host and service pointing to mock server
    let host: (i64,) = sqlx::query_as(
        "INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('127.0.0.1'::inet, $1, $1) RETURNING id",
    )
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let svc: (i64,) = sqlx::query_as(
        "INSERT INTO services (host_id, port, transport, data, first_seen, last_seen) VALUES ($1, $2, 'tcp', $3, $4, $4) RETURNING id",
    )
    .bind(host.0)
    .bind(addr.port() as i32)
    .bind(serde_json::json!({"kind": "http", "http": {"status": 200, "title": "Test"}}))
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let assets_dir = tempfile::tempdir().unwrap();
    let assets_path = assets_dir.path().to_str().unwrap();

    // Run the enricher
    favicon::fetch_and_store(&pool, svc.0, assets_path).await.unwrap();

    // Verify the asset was stored in DB
    let asset: (String, i64) = sqlx::query_as(
        "SELECT sha256, taken_at FROM service_assets WHERE service_id = $1 AND kind = 'favicon'",
    )
    .bind(svc.0)
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(!asset.0.is_empty(), "sha256 should not be empty");
    assert!(asset.1 > 0, "taken_at should be set");

    // Verify the favicon hash was written to JSONB
    let data: (serde_json::Value,) = sqlx::query_as(
        "SELECT data FROM services WHERE id = $1",
    )
    .bind(svc.0)
    .fetch_one(&pool)
    .await
    .unwrap();

    let favicon_hash = data.0.pointer("/http/favicon_hash");
    assert!(favicon_hash.is_some(), "favicon_hash should be set");
    assert!(favicon_hash.unwrap().is_number(), "favicon_hash should be a number");

    // Verify the file exists on disk
    let file_path = assets_dir.path().join(format!("{}.ico", asset.0));
    assert!(file_path.exists(), "favicon file should exist on disk");
}

#[sqlx::test(migrations = "./migrations")]
async fn test_enrich_favicon_404(pool: sqlx::PgPool) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response).await.ok();
    });

    let host: (i64,) = sqlx::query_as(
        "INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('127.0.0.1'::inet, $1, $1) RETURNING id",
    )
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let svc: (i64,) = sqlx::query_as(
        "INSERT INTO services (host_id, port, transport, data, first_seen, last_seen) VALUES ($1, $2, 'tcp', '{}', $3, $3) RETURNING id",
    )
    .bind(host.0)
    .bind(addr.port() as i32)
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let assets_dir = tempfile::tempdir().unwrap();

    // Should not error — just skip gracefully
    favicon::fetch_and_store(&pool, svc.0, assets_dir.path().to_str().unwrap())
        .await
        .unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM service_assets WHERE service_id = $1")
        .bind(svc.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "no asset should be created for 404");
}
