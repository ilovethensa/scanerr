# Deepscan Stage Analysis

**Date:** 2026-08-28  
**Status:** ANALYSIS COMPLETE — ready for implementation  
**Updated:** 2026-08-28 (corrected root cause per REPORT.md)

## Executive Summary

The deepscan stage is **crash-looping due to container OOM kills** caused by **unbounded masscan concurrency**. Each deepscan replica spawns masscan subprocesses via `spawn_blocking` without awaiting the JoinHandle, then immediately reclaims the next host. This accumulates hundreds of concurrent masscan processes per replica, exceeding the 512MB cgroup limit.

**Current state:** 45-51 restarts per container, 1,616 hosts stuck in queue, probe stage idle (0 items).

## Root Cause: Unbounded Masscan Concurrency

### The Bug

`run_deepscan()` at `src/main.rs:201-263`:
```rust
loop {
    let claimed = claim_host_scans(&pool, 1, t).await?;  // claim 1 host
    for (id, ip) in claimed {
        tokio::task::spawn_blocking(move || {              // spawn masscan
            masscan::run_stage2(&ip, &ports, rate)
                .unwrap_or_default()                       // error swallowed
        });                                                // ← JoinHandle DROPPED, not awaited
    }
    // loop immediately reclaims next host — no wait
}
```

The `spawn_blocking` returns a `JoinHandle` that is **never awaited**. The loop immediately reclaims the next host and spawns another. One replica accumulates **unbounded concurrent masscan subprocesses** (only capped by tokio's blocking pool ~512). With 4 replicas, this is exactly what `dmesg` shows being OOM-killed.

### Why Previous Fixes Were Wrong

- **"batch=1"** only limits rows per claim query, not in-flight tasks
- **"512MB limit"** is insufficient when scanerr (145MB) + multiple masscan instances (300-400MB each) share a cgroup
- **"raise replicas to 8"** would have made OOM *worse* (more concurrent masscan)

### Evidence

```
# dmesg shows cgroup-level OOM kills
oom-kill: constraint=CONSTRAINT_MEMCG, task=scanerr, pid=...
masscan invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL)

# Container restart counts (climbing continuously)
deepscan-1: restarts=51
deepscan-2: restarts=48
deepscan-3: restarts=47
deepscan-4: restarts=45

# Host queue stuck at 1,616 — not draining
host_q=1616, probe_q=0, enrich_q=0
```

## Fix Plan (from REPORT.md)

### Step 1: Bound in-flight masscan per replica (PRIMARY FIX)

Use `tokio::sync::Semaphore` with ~2 permits per replica. 4 replicas × 2 = 8 concurrent masscan max.

```rust
let sem = Arc::new(Semaphore::new(2));
loop {
    let claimed = claim_host_scans(&pool, 1, t).await?;
    for (id, ip) in claimed {
        let permit = sem.clone().acquire_owned().await?;
        let pool = pool.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit; // held until block completes
            masscan::run_stage2(&ip, &ports, rate)
                .unwrap_or_default()
        });
    }
}
```

### Step 2: Add sweep() to deepscan for stale claims

Currently OOM-crashed hosts are orphaned in the queue (claimed but never completed/deleted). Add `sweep()` + `increment_attempts()` so crashed hosts get requeued or deleted.

### Step 3: Add `--wait 1` to masscan

masscan defaults to 10s idle wait after last response. Adding `--wait 1` cuts per-host scan time significantly and reduces peak memory.

### Step 4: Log masscan errors

Replace `.unwrap_or_default()` with proper error logging so OOM kills and masscan failures are visible.

## Secondary Issues

### Backfill Slow Query on Restart

Every deepscan restart runs `backfill()` → `SELECT id, data FROM services` (13K rows, 1.3-4.8s). With 45-51 restarts per container, this fires hundreds of times. Fix owned by Agent 1.

### Claim Query COALESCE

`WHERE COALESCE(claimed_until, 0) < $2` prevents btree index usage. Fix owned by Agent 2.

## What NOT to Do

- **Do NOT raise deepscan replicas or deep_scan_rate** — worsens OOM until concurrency is bounded
- **Do NOT increase memory limit to 1GB** — the real issue is concurrency, not total memory
- **Do NOT reduce replicas** — 4 is fine once concurrency is bounded (4×2 = 8 concurrent masscan)

## Verification

```sh
cargo check && cargo test
./deploy.sh
# Watch RSS
docker stats scanerr-deepscan-{1..4}
# Watch OOM
dmesg | grep -i oom | tail
# Watch queue drain
docker exec scanerr-postgres-1 psql -U scanerr -d scanerr -t -A -c \
  "SELECT (SELECT count(*) FROM queue_host_scans) AS host_q"
```
