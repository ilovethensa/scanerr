//! Full workflow integration test:
//!   queue_host_scans → queue_service_probes → probe (mock HTTP) → enrich (mock favicon) → verify DB + API

use scanerr::enrich::favicon;
use scanerr::fingerprint::Engine;
use scanerr::probe::dispatch;
use scanerr::queue;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Spawn a mock HTTP server that serves a page + favicon, returns (ip, port).
async fn spawn_mock_server() -> (String, u16) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);

            if request.contains("favicon.ico") {
                let favicon: &[u8] = &[
                    0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
                    0x01, 0x00, 0x18, 0x00, 0x30, 0x00, 0x00, 0x00, 0x16, 0x00,
                    0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: image/x-icon\r\nConnection: close\r\n\r\n",
                    favicon.len()
                );
                stream.write_all(header.as_bytes()).await.ok();
                stream.write_all(favicon).await.ok();
            } else {
                let body = "<html><head><title>Proxmox VE Login</title></head><body><h1>Proxmox VE</h1></body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.ok();
            }
        }
    });

    ("127.0.0.1".to_string(), port)
}

#[sqlx::test(migrations = "./migrations")]
async fn test_full_workflow(pool: sqlx::PgPool) {
    let t = now();

    // Install rustls crypto provider for TLS tests
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ================================================================
    // STEP 1: Simulate scan — insert IPs into queue_host_scans
    // ================================================================
    queue::insert_host_scan(&pool, "127.0.0.1").await.unwrap();

    let host_queue = queue::LeasedQueue::new("queue_host_scans");
    let items = host_queue.claim_host_scans(&pool, 10, t).await.unwrap();
    assert_eq!(items.len(), 1, "should claim 1 host from scan queue");
    let (host_scan_id, _ip) = &items[0];

    // ================================================================
    // STEP 2: Simulate deep scan — insert ports into queue_service_probes
    // ================================================================
    // (We skip actual masscan and directly insert probes for our mock server)
    let mock_ip = "127.0.0.1";
    let mock_port: u16 = 80; // Will be overridden below
    let _ = (mock_ip, mock_port);

    let probe_queue = queue::LeasedQueue::new("queue_service_probes");

    // Heartbeat the host scan so it doesn't expire
    host_queue.heartbeat(&pool, *host_scan_id, t).await.unwrap();

    // ================================================================
    // STEP 3: Probe — spin up mock, insert probe job, run dispatch
    // ================================================================
    let (ip, port) = spawn_mock_server().await;

    queue::insert_service_probe(&pool, &ip, port as i32, "tcp").await.unwrap();

    let items = probe_queue.claim_service_probes(&pool, 10, t).await.unwrap();
    assert_eq!(items.len(), 1, "should claim 1 probe job");

    let (probe_id, probe_ip, probe_port, probe_transport) = &items[0];

    let engine = Engine::from_signatures(vec![]);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .unwrap();

    let result = dispatch::probe(
        &pool,
        probe_ip,
        *probe_port as u16,
        probe_transport,
        "scanerr-test/1.0",
        None, // no GeoIP
        &client,
        &engine,
    )
    .await
    .expect("probe should succeed");

    // Verify probe result
    assert_eq!(result.ip, ip);
    assert_eq!(result.port, port);
    assert_eq!(result.data.kind, "http");
    assert!(result.data.tags.contains(&"http".to_string()));

    let http_data = result.data.http.as_ref().unwrap();
    assert_eq!(http_data.status, 200);
    assert_eq!(http_data.title.as_deref(), Some("Proxmox VE Login"));
    assert!(http_data.headers.contains_key("server"));

    // Upsert service into DB
    let service_id = dispatch::upsert_service(&pool, &result).await.unwrap();
    assert!(service_id > 0, "service_id should be positive");

    // ================================================================
    // STEP 4: Fingerprint — run identify() on the service data
    // ================================================================
    let mut data = result.data.clone();
    let engine = Engine::from_signatures(vec![]);
    engine.identify(&mut data);

    // Should match both nginx (server header) and proxmox (title) signatures
    assert!(data.tags.contains(&"web".to_string()));
    assert!(data.tags.contains(&"server".to_string()));
    assert!(data.tags.contains(&"iot".to_string()));

    // Update the service data with fingerprinted version
    sqlx::query("UPDATE services SET data = $1 WHERE id = $2")
        .bind(serde_json::to_value(&data).unwrap())
        .bind(service_id)
        .execute(&pool)
        .await
        .unwrap();

    // ================================================================
    // STEP 5: Enrich — fetch favicon from mock server
    // ================================================================
    let assets_dir = tempfile::tempdir().unwrap();
    favicon::fetch_and_store(&pool, service_id, assets_dir.path().to_str().unwrap())
        .await
        .expect("enrich should succeed");

    // Verify asset stored in DB
    let asset: (String,) = sqlx::query_as(
        "SELECT sha256 FROM service_assets WHERE service_id = $1 AND kind = 'favicon'",
    )
    .bind(service_id)
    .fetch_one(&pool)
    .await
    .expect("asset should exist");
    assert!(!asset.0.is_empty());

    // Verify favicon_hash in JSONB
    let row: (serde_json::Value,) = sqlx::query_as("SELECT data FROM services WHERE id = $1")
        .bind(service_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let hash = row.0.pointer("/http/favicon_hash").unwrap();
    assert!(hash.is_number(), "favicon_hash should be a number in JSONB");

    // Verify file on disk
    assert!(
        assets_dir.path().join(format!("{}.ico", asset.0)).exists(),
        "favicon file should exist"
    );

    // ================================================================
    // STEP 6: Verify full data in DB via queries (simulating serve)
    // ================================================================

    // Search by port
    let search_sql = "SELECT s.id, s.port, s.transport, s.sni, s.data, s.first_seen, s.last_seen, \
                      h.ip::text, h.country_code, h.asn, h.org \
                      FROM services s JOIN hosts h ON s.host_id = h.id \
                      WHERE port = $1::int ORDER BY s.last_seen DESC LIMIT 100";
    let results: Vec<(i64, i32, String, Option<String>, serde_json::Value, i64, i64, String, Option<String>, Option<i32>, Option<String>)> =
        sqlx::query_as(search_sql)
            .bind(port.to_string())
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(results.len(), 1, "should find 1 service on this port");
    assert_eq!(results[0].1, port as i32);

    // Search by tag — use a tag that's present after fingerprinting
    let tag_sql = "SELECT s.id FROM services s WHERE data->'tags' ? $1";
    let tagged: Vec<(i64,)> = sqlx::query_as(tag_sql)
        .bind("iot")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(tagged.len(), 1, "should find 1 service tagged 'iot'");

    // JSONB containment search (Shodan-style)
    let jsonb_sql = "SELECT s.id FROM services s WHERE data @> $1::jsonb";
    let contained: Vec<(i64,)> = sqlx::query_as(jsonb_sql)
        .bind(serde_json::json!({"http": {"title": "Proxmox VE Login"}}))
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(contained.len(), 1, "JSONB containment should match");

    // ================================================================
    // STEP 7: Cleanup — sweep expired queues
    // ================================================================
    probe_queue.heartbeat(&pool, *probe_id, t).await.unwrap();

    // Simulate lease expiry
    sqlx::query("UPDATE queue_service_probes SET claimed_until = $1")
        .bind(t - 600)
        .execute(&pool)
        .await
        .unwrap();

    let deleted = probe_queue.sweep(&pool, 3, t).await.unwrap();
    assert_eq!(deleted, 0, "should requeue, not delete (attempts < 3)");

    // Verify host exists with correct data
    let host: (String, Option<String>) = sqlx::query_as(
        "SELECT ip::text, reverse_dns FROM hosts WHERE id = $1",
    )
    .bind(result.host_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(host.0.starts_with("127.0.0.1"), "IP should be 127.0.0.1, got {}", host.0);

    println!("Full workflow test passed!");
    println!("  Host ID: {}", result.host_id);
    println!("  Service ID: {}", service_id);
    println!("  Asset SHA256: {}", asset.0);
    println!("  Favicon hash: {}", hash);
    println!("  Product: {:?}", data.product);
    println!("  Tags: {:?}", data.tags);
}
