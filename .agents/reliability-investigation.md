# Reliability Investigation — Agent Notes

**Date:** 2026-08-28
**Status:** In Progress

## Current State

- **13106 services** across **5693 hosts**
- Breakdown: 5430 HTTP (41%), 2102 SSH (16%), 3276 unknown (25%), ~2298 other (18%)
- Queue status: service_probes empty (keeping up), host_scans 1504 claimed (all active), enrichments empty
- Pipeline running: sweep → deepscan (4 replicas) → probe (4 replicas) → enrich → serve
- All containers healthy but showing performance issues

---

## Issue #1: `backfill()` loads entire services table on every restart (CRITICAL)

**File:** `src/normalize.rs:205-234`

Every time `sweep` or `deepscan` starts, it calls `normalize::backfill()`:
```rust
let rows: Vec<(i64, serde_json::Value)> = sqlx::query("SELECT id, data FROM services")
    .fetch_all(pool)  // <-- loads ALL 13096 rows into memory
    .await?
```

This runs:
- On every container restart (sweep-1, deepscan-1/2/3/4)
- Takes 1.3s–8s per execution
- Each row is deserialized, normalized, compared, and conditionally updated
- 5 containers × every restart = massive DB load

**Impact:** Slow query warnings every 5-6 seconds from deepscan containers. The query itself is the bottleneck.

**Fix:** The backfill is idempotent. It only needs to run once (or when normalization logic changes). Options:
1. Track a `normalize_version` in the DB and skip if current
2. Run backfill as a one-shot migration, not on every startup
3. Use a dirty flag — only backfill if a version marker in the code differs from what's in the DB

---

## Issue #2: Massive probe timeouts (~50% failure rate)

**Evidence from logs:**
```
probe-2: Probe timed out for 2.56.54.63/32:80
probe-2: Probe timed out for 2.56.54.70/32:80
probe-2: Probe timed out for 2.56.55.65/32:80
probe-3: Probe timed out for 2.56.53.146/32:80
probe-3: Probe timed out for 2.56.53.148/32:80
... (dozens more)
```

**Root cause:** The `probe_timeout` is configured (likely 5s per `scanerr.toml`), but many targets simply don't respond. The probe workers claim 10 items at a time (`claim_service_probes(..., 10, ...)`), and if 5 of those timeout, that's 25s of wasted time per batch.

**Impact:** Probe throughput is severely reduced. Many ports that respond slowly (or to specific probes) are marked as failed and requeued, creating retry storms.

**Fix options:**
1. Reduce claim batch size from 10 to 3-5 so timeouts don't block the queue as long
2. Add per-protocol connect timeouts (e.g., 2s for TCP connect, 3s for HTTP)
3. Use `tokio::select!` with separate connect/read timeouts instead of one outer timeout

---

## Issue #3: Claim query slow on empty queue (1.5s)

**Evidence:**
```
probe-1: slow statement: "WITH claimed AS (UPDATE queue_service_probes ...)"
  rows_returned=0, elapsed=1.539s
```

When the queue is empty, the `FOR UPDATE SKIP LOCKED` query takes 1.5s. With 4 probe replicas all polling, that's 4 queries/1.5s hitting the DB.

**Root cause:** The query uses `COALESCE(claimed_until, 0) < $2`. There IS a btree index on `(claimed_until, id)` (migration `20260828000000_queue_claim_indexes.sql`), but COALESCE may prevent index usage. The old partial indexes were dropped in favor of composite btree indexes.

**Fix:** The COALESCE wrapping might prevent the index scan. Consider:
1. Changing the WHERE to `WHERE claimed_until IS NULL OR claimed_until < $2` (let planner use index)
2. Or: set `claimed_until = 0` instead of NULL when inserting, so COALESCE is unnecessary
3. Check with EXPLAIN ANALYZE to see if the btree index is actually being used

---

## Issue #4: Deepscan `SELECT id, data FROM services` appears in deepscan logs too

The deepscan containers show this query too, even though deepscan doesn't probe services. This is from the `backfill()` call at startup. But it also suggests deepscan might be reading the services table for honeypot detection.

**File:** `src/main.rs:243` — the honeypot check in deepscan does:
```sql
UPDATE hosts SET is_honeypot = true WHERE ip = $1
AND (SELECT count(*)::int FROM services WHERE host_id = $1) > 50
```
This is fine (correlated subquery, indexed by host_id). The big SELECT is from backfill.

---

## Issue #5: Enrichment retry not implemented

**File:** `src/main.rs:370-386`

Enrichment failures are logged but not retried:
```rust
if let Err(err) = e.run(&pool, service_id, &assets_dir).await {
    tracing::error!("Enrichment failed for service {}: {}", service_id, err);
}
let _ = enrich_queue.complete(&pool, id).await;  // <-- deleted even on failure
```

The item is deleted from the queue on failure. No retry. The `attempts` field in `queue_enrichments` is never incremented.

**Impact:** Failed enrichments (e.g., favicon fetch got 400/404) are silently dropped. This is actually correct for 404s (no favicon exists), but network errors should be retried.

---

## Files to Investigate

| File | What to look at |
|------|----------------|
| `src/normalize.rs:205-234` | backfill() — needs versioning/skip logic |
| `src/queue.rs` | claim query optimization, COALESCE index |
| `src/main.rs:201-263` | deepscan loop — check for redundant queries |
| `src/probe/dispatch.rs` | probe flow — timeout handling |
| `src/probe/engine.rs` | dispatch chain — fallback overhead |
| `scanerr.toml` | timeout settings, claim batch sizes |
| `deploy.sh` | deployment flow — no issues, works well |
| `docker-compose.yml` | resource limits — probe at 256MB may be tight |
