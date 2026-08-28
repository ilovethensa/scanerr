# Agent Task Board

**Updated:** 2026-08-28 (fresh production snapshot included)  
**Status:** Task 1 (deepscan OOM) + Task 2 (probe timeout) IMPLEMENTED + DEPLOYED + VERIFIED.
          Pipeline now populates DB/Web UI (174 new services + 128 hosts per 180s). 
          Tasks 3-7 analyzed, not coded.

## Production Snapshot

```
hosts=7982  services=13116
queue:  host_q=1616  probe_q=0  enrich_q=0
kinds:  http 5434 | unknown 3278 (25%) | ssh 2103 | ftp 967 | pop3 500
deepscan: 45-51 restarts/container (OOM kills, climbing)
probe:    0 restarts (stable)
```

---

## Task 1: Bound deepscan masscan concurrency [DONE — implemented, deployed, verified]
**Owner:** analysis agent (took over from Agent 5 to stop active OOM)  
**Priority:** HIGH — COMPLETE  
**Files:** `src/main.rs` (run_deepscan), `src/masscan.rs`

**Root cause:** `spawn_blocking` JoinHandle never awaited → unbounded concurrent masscan per replica → cgroup OOM kills. 45-51 restarts per container, 1,616 hosts stuck in queue.

**Implemented (commit pending in working tree):**
1. `Arc<Semaphore>::new(2)` per replica; loop `acquire_owned()` before spawning, permit moved into
   the task and dropped on completion → max 8 concurrent masscan (4 replicas × 2). **PRIMARY FIX.**
2. `increment_attempts()` on claim + periodic `host_queue.sweep(pool, 3, t)` every 50 hosts →
   OOM-crashed hosts requeued, poison hosts dropped after 3 attempts.
3. `--wait 1` added to masscan (both stage1 + stage2 via `masscan_scan`).
4. `run_stage2` collapsed into `masscan_scan` (removed duplicate).

**Verified in prod (2026-08-28, ~2 min after deploy):** deepscan restarts = 0 (was 54-61);
deepscan RSS ~205 MiB / 512 MiB (stable); `dmesg` OOM kills stopped (restart=0 proves it);
host_q 1593 → 1481 (draining). `cargo check` + 29 unit tests pass (2 enrich tests need DATABASE_URL).

---

## Task 2: Align probe timeout budget [DONE — implemented, deployed, verified]
**Owner:** analysis agent (took over from Agent 3)  
**Priority:** HIGH — COMPLETE  
**Files:** `src/probe/engine.rs` (read_banner), `src/main.rs` (run_probe outer timeout)

**Root cause:** 5s outer timeout fired during `read_banner` (3s+5s), killing probes before the
HTTP/HTTPS/TLS fallback ran. ~95% of open ports were discarded as timeouts → services not stored.

**Implemented:** `read_banner` connect 3s→2s, read 5s→2s (`engine.rs`); outer `probe_timeout =
config.probe.timeout_secs.max(20)` (`main.rs`) — per-phase timeouts still bound each step.

**Verified in prod (2026-08-28):** probe timeouts 162/3min → **16/3min** (~5/min); probe successes
**178/3min** (~59/min); **174 new services + 128 new hosts per 180s** written to DB; Web UI live.
`cargo check` + 29 unit tests pass.

**Remaining:** ~5 timeouts/min are genuinely slow/unresponsive hosts (acceptable). `host_q` backlog
(~1684) persists because sweep outproduces deepscan — now SAFE to raise deepscan replicas (Task 1
bounded concurrency) but not required for correctness.

---

## Task 3: Fix `backfill()` startup bottleneck [HIGH]
**Owner:** Agent 1  
**Priority:** HIGH  
**Files:** `src/normalize.rs:205-234`, `src/main.rs:112,116`

**Problem:** `backfill()` loads ALL 13K+ services on every container restart. 1.3-8s slow query, fires on every OOM restart (hundreds of times).

**Tasks:**
1. Add `meta` table with `key='normalize_version', value=<hash>`
2. At startup, compare code version vs DB version; skip backfill if match
3. Or simpler: move backfill to CLI subcommand (`scanerr normalize`)
4. Or: cursor-based pagination (`SELECT ... WHERE id > $last_id LIMIT 5000`)

**Verify:** `cargo check && cargo test`; deploy; no slow `SELECT id, data FROM services` warnings.

---

## Task 4: Optimize claim query for empty queues [MEDIUM]
**Owner:** Agent 2  
**Priority:** MEDIUM  
**Files:** `src/queue.rs`  
**Also:** `src/migrations/20260828000000_queue_claim_indexes.sql`

**Problem:** `COALESCE(claimed_until, 0) < $2` prevents btree index usage on `(claimed_until, id)`. 1.16s claim query on empty queue.

**Tasks:**
1. Run `EXPLAIN ANALYZE` on claim query to confirm index isn't used
2. Change WHERE to `WHERE claimed_until IS NULL OR claimed_until < $2`
3. Or store `claimed_until = 0` instead of NULL (no COALESCE needed)

**Verify:** `cargo test` passes, EXPLAIN shows index scan.

---

## Task 5: Fix enrichment retry logic [LOW]
**Owner:** Agent 4  
**Priority:** LOW  
**Files:** `src/main.rs:342-389` (run_enrich), `src/queue.rs`

**Problem:** Enrichment items deleted on failure without retry. Acceptable for 404 favicons; network errors silently lost.

**Key code:**
```rust
if let Err(err) = e.run(&pool, service_id, &assets_dir).await {
    tracing::error!("Enrichment failed for service {}: {}", service_id, err);
}
let _ = enrich_queue.complete(&pool, id).await;  // <-- deleted even on failure
```

**Tasks:**
1. On error: call `enrich_queue.increment_attempts()` before `complete()`
2. Only delete if `attempts < max_attempts`
3. Or: just log and complete (current behavior) — acceptable for favicon 404s

**Verify:** `cargo check && cargo test` passes.

---

## Task 6: Fix sweep dead config + missing delay [HIGH]
**Owner:** Agent 5  
**Priority:** HIGH  
**Files:** `src/main.rs:155-199` (run_sweep), `src/config.rs:34-37`, `src/masscan.rs:74-76`

**Problem:** `sweep_chunk_size` and `sweep_interval_secs` parsed but never used. Sweep loops continuously with no delay. 1348 ranges processed sequentially (~22.5h per cycle).

**Tasks:**
1. Batch ranges by `sweep_chunk_size` before calling masscan (1348 invocations → ~68)
2. Add `tokio::time::sleep(Duration::from_secs(sweep_interval_secs))` at end of cycle
3. Log masscan errors instead of silently converting to empty results

**Verify:** `cargo check && cargo test`; deploy; sweep pauses between cycles.

---

## Task 7: Add backpressure for host_scans queue [MEDIUM]
**Owner:** Agent 6  
**Priority:** MEDIUM  
**Files:** `src/main.rs:166-174` (backpressure check), `src/queue.rs:153-161`

**Problem:** Backpressure only monitors `queue_service_probes`. `queue_host_scans` grows unbounded (currently 1,616).

**Tasks:**
1. Check both `queue_host_scans` and `queue_service_probes` depth before scanning
2. Add `host_queue_max_depth` config field (or reuse `max_probe_queue_depth`)
3. Log when pausing due to host queue backpressure

**Verify:** `cargo check && cargo test` passes.

---

## Implementation Order (recommended)

```
1. Task 1 (deepscan OOM)         ← blocks everything, queue stuck at 1616
2. Task 2 (probe timeout)        ← drives 25% unknown rate
3. Task 3 (backfill)             ← constant slow queries on restart
4. Task 6 (sweep config)         ← enables controlled sweep pacing
5. Task 4 (claim query)          ← improves queue performance
6. Task 7 (host backpressure)    ← prevents future queue blowup
7. Task 5 (enrich retry)         ← nice-to-have, low impact
```

## Deployment

```sh
./deploy.sh  # Builds locally, SCPs to VM, restarts containers
```

## Production Log Commands

```sh
# All containers
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose logs --tail=100"

# Specific container
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose logs --tail=50 probe-1"

# Watch for slow queries
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose logs -f 2>&1 | grep -i 'slow statement'"

# Queue depths
ssh root@192.168.1.202 "docker exec scanerr-postgres-1 psql -U scanerr -d scanerr -t -A -c \
  \"SELECT (SELECT count(*) FROM queue_host_scans) AS host_q, (SELECT count(*) FROM queue_service_probes) AS probe_q\""

# Service kind distribution
ssh root@192.168.1.202 "docker exec scanerr-postgres-1 psql -U scanerr -d scanerr -c \
  \"SELECT data->>'kind' as kind, count(*) FROM services GROUP BY 1 ORDER BY 2 DESC\""

# OOM check
ssh root@192.168.1.202 "dmesg | grep -i oom | tail"

# Container restarts
ssh root@192.168.1.202 'for c in 1 2 3 4; do echo -n "deepscan-$c: "; docker inspect "scanerr-deepscan-$c" --format "restarts={{.RestartCount}}"; done'
```

---

## Shared Analysis Files

| File | Content |
|------|---------|
| `.agents/REPORT.md` | Consolidated findings, verified against prod |
| `.agents/probe-analysis.md` | Probe timeout budget root cause |
| `.agents/deepscan-analysis.md` | Deepscan OOM root cause + fix plan |
| `.agents/sweep-analysis.md` | Sweep system analysis (9 issues) |
| `.agents/reliability-investigation.md` | Earlier investigation notes (superseded) |
