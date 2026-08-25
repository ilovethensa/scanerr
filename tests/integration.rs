use scanerr::queue;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[sqlx::test(migrations = "./migrations")]
async fn test_queue_host_scans_claim_and_heartbeat(pool: sqlx::PgPool) {
    // Insert some test IPs
    for ip in &["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
        queue::insert_host_scan(&pool, ip).await.unwrap();
    }

    let q = queue::LeasedQueue::new("queue_host_scans");
    let t = now();

    // Claim a batch of 2
    let items = q.claim_host_scans(&pool, 2, t).await.unwrap();
    assert_eq!(items.len(), 2, "should claim 2 items");

    // Verify claimed items have future claimed_until
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT claimed_until FROM queue_host_scans WHERE id = $1",
    )
    .bind(items[0].0)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0.is_some(), "claimed_until should be set");
    assert!(row.0.unwrap() > t, "claimed_until should be in the future");

    // Heartbeat one item
    q.heartbeat(&pool, items[0].0, t).await.unwrap();

    // Claim remaining — should get the unclaimed one
    let items2 = q.claim_host_scans(&pool, 10, t).await.unwrap();
    assert_eq!(items2.len(), 1, "should claim the 1 remaining unclaimed item");
}

#[sqlx::test(migrations = "./migrations")]
async fn test_queue_host_scans_sweep(pool: sqlx::PgPool) {
    queue::insert_host_scan(&pool, "10.0.0.1").await.unwrap();
    queue::insert_host_scan(&pool, "10.0.0.2").await.unwrap();

    let q = queue::LeasedQueue::new("queue_host_scans");
    let t = now();

    // Claim both
    let items = q.claim_host_scans(&pool, 10, t).await.unwrap();
    assert_eq!(items.len(), 2);

    // Expire the lease by setting claimed_until to the past
    sqlx::query("UPDATE queue_host_scans SET claimed_until = $1, attempts = 0")
        .bind(t - 600)
        .execute(&pool)
        .await
        .unwrap();

    // Sweep with max_attempts=3 — should requeue (attempts < 3)
    let deleted = q.sweep(&pool, 3, t).await.unwrap();
    assert_eq!(deleted, 0, "should not delete, just requeue");

    // Verify both are requeued (claimed_until = NULL)
    let unclaimed: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM queue_host_scans WHERE claimed_until IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unclaimed.0, 2, "both should be requeued");

    // Now bump attempts past max and sweep again
    sqlx::query("UPDATE queue_host_scans SET claimed_until = $1, attempts = 5")
        .bind(t - 600)
        .execute(&pool)
        .await
        .unwrap();

    let deleted = q.sweep(&pool, 3, t).await.unwrap();
    assert_eq!(deleted, 2, "should delete both (attempts >= max)");
}

#[sqlx::test(migrations = "./migrations")]
async fn test_queue_service_probes(pool: sqlx::PgPool) {
    queue::insert_service_probe(&pool, "10.0.0.1", 80, "tcp").await.unwrap();
    queue::insert_service_probe(&pool, "10.0.0.1", 443, "tcp").await.unwrap();
    queue::insert_service_probe(&pool, "10.0.0.2", 22, "tcp").await.unwrap();

    let q = queue::LeasedQueue::new("queue_service_probes");
    let t = now();

    let items = q.claim_service_probes(&pool, 2, t).await.unwrap();
    assert_eq!(items.len(), 2);

    // Verify IP and port are correct
    for (_id, ip, port, transport) in &items {
        assert!(!ip.is_empty());
        assert!(*port > 0);
        assert_eq!(transport, "tcp");
    }

    // One remains unclaimed
    let remaining = q.claim_service_probes(&pool, 10, t).await.unwrap();
    assert_eq!(remaining.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn test_queue_enrichments(pool: sqlx::PgPool) {
    // Insert a host and service first
    let host: (i64,) = sqlx::query_as(
        "INSERT INTO hosts (ip, first_seen, last_seen) VALUES ('10.0.0.1'::inet, $1, $1) RETURNING id",
    )
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    let svc: (i64,) = sqlx::query_as(
        "INSERT INTO services (host_id, port, transport, data, first_seen, last_seen) VALUES ($1, 80, 'tcp', '{}', $2, $2) RETURNING id",
    )
    .bind(host.0)
    .bind(now())
    .fetch_one(&pool)
    .await
    .unwrap();

    queue::insert_enrichment(&pool, svc.0, "favicon", now()).await.unwrap();
    queue::insert_enrichment(&pool, svc.0, "screenshot", now()).await.unwrap();

    let q = queue::LeasedQueue::new("queue_enrichments");
    let t = now();

    let items = q.claim_enrichments(&pool, 10, t).await.unwrap();
    assert_eq!(items.len(), 2, "should claim both enrichment types");

    let kinds: Vec<&str> = items.iter().map(|(_, _, k)| k.as_str()).collect();
    assert!(kinds.contains(&"favicon"));
    assert!(kinds.contains(&"screenshot"));
}

#[sqlx::test(migrations = "./migrations")]
async fn test_backpressure(pool: sqlx::PgPool) {
    // Empty queue — no backpressure
    assert!(!queue::backpressure_active(&pool, 5).await.unwrap());

    // Insert 5 items
    for i in 0..5 {
        queue::insert_service_probe(&pool, &format!("10.0.0.{}", i), 80, "tcp").await.unwrap();
    }

    // Exactly at threshold — should be active
    assert!(queue::backpressure_active(&pool, 5).await.unwrap());

    // Below threshold
    assert!(!queue::backpressure_active(&pool, 10).await.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn test_queue_dedup(pool: sqlx::PgPool) {
    // Insert same IP twice — should deduplicate
    queue::insert_host_scan(&pool, "10.0.0.1").await.unwrap();
    queue::insert_host_scan(&pool, "10.0.0.1").await.unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM queue_host_scans")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "should deduplicate");

    // Same for service probes
    queue::insert_service_probe(&pool, "10.0.0.1", 80, "tcp").await.unwrap();
    queue::insert_service_probe(&pool, "10.0.0.1", 80, "tcp").await.unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM queue_service_probes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1, "should deduplicate");
}
