# Sweep System Analysis

**Date:** 2026-08-28

## Overview

The sweep is Stage 1 of the pipeline: masscan broad discovery across CIDR ranges, inserting alive hosts into `queue_host_scans` for deepscan.

## Flow

```
run_sweep() [src/main.rs:155]
  └─ for each range in ranges.txt:
       ├─ check backpressure (service_probes queue depth)
       ├─ masscan::run_stage1_batch([range], discovery_ports, rate)  [blocking]
       ├─ for each alive host: INSERT INTO queue_host_scans ON CONFLICT DO NOTHING
       └─ log "Sweep chunk: found X alive hosts"
  └─ loop back to first range (no delay)
```

## Configuration

```toml
discovery_ports = [80, 443, 7547, 554, 22, 53, 8080, 179, 2000, 123, 23, 81, 1883, 5000, 8000, 8001, 8002, 8081, 8888, 37777]
discovery_rate = 1000
sweep_chunk_size = 20          # NOT USED in code
sweep_interval_secs = 3600     # NOT USED in code
max_probe_queue_depth = 50000  # backpressure threshold
```

## Production Timing (from logs)

| Range | CIDR | Alive Hosts | Scan Time |
|-------|------|-------------|-----------|
| 2.56.12.0/22 | /22 | 53 | ~78s |
| 2.56.52.0/22 | /22 | 804 | ~82s |
| 2.58.92.0/24 | /24 | 14 | ~33s |
| 2.58.95.0/24 | /24 | 699 | ~40s |
| 2.59.252.0/22 | /22 | 632 | ~84s |

**Average:** ~60s per range

## Scale

- **1348 ranges** in ranges.txt
- At ~60s per range, sequential: **~22.5 hours** for a full sweep cycle
- Sweep interval config (`sweep_interval_secs = 3600`) is defined but **never used** — the loop runs continuously with no delay

---

## Issues Found

### Issue #1: `sweep_chunk_size` and `sweep_interval_secs` are dead config

**File:** `src/main.rs:155-199`, `src/config.rs:34-37`

Both config fields exist in `scanerr.toml` and are parsed, but `run_sweep()` never reads them:
- `sweep_chunk_size`: intended to batch multiple ranges per masscan invocation, but the code sends one range at a time
- `sweep_interval_secs`: intended to add a delay between sweep cycles, but the loop has no sleep

**Impact:** No way to control sweep pacing. The sweep runs as fast as possible, which wastes bandwidth and CPU on repeated scanning of the same ranges.

### Issue #2: No delay between sweep cycles

**File:** `src/main.rs:197-198`

```rust
info!("Sweep finished — re-scanning all ranges");
// immediately loops back — no sleep
```

After scanning all 1348 ranges (~22.5 hours), the sweep immediately starts over. There's no configurable cooldown period.

**Impact:** Continuous scanning with no rest. Could cause rate limiting or blocking by upstream ISPs.

### Issue #3: Sequential range processing

**File:** `src/main.rs:164`

Ranges are scanned one at a time in a `for` loop. With 1348 ranges, this is extremely slow.

**Impact:** Full sweep takes ~22.5 hours. New ranges scanned later in the cycle have significantly higher latency from discovery to deepscan.

### Issue #4: Masscan invocation is per-range, not batched

**File:** `src/masscan.rs:74-76`

```rust
pub fn run_stage1_batch(ranges: &[String], ports: &[u16], rate: u32) -> Result<Vec<ScanResult>> {
    masscan_scan(ranges, ports, rate)  // wraps in vec
}
```

The function accepts multiple ranges but `run_sweep()` passes only one at a time: `masscan::run_stage1_batch(&[range_clone], ...)`. Even though masscan can scan multiple CIDRs in one invocation, the code doesn't batch them.

**Impact:** Unnecessary process spawning overhead (1348 masscan processes per cycle instead of ~68 with chunk_size=20).

### Issue #5: Backpressure only checks service_probes queue

**File:** `src/main.rs:166-174`, `src/queue.rs:153-161`

```rust
pub async fn backpressure_active(pool: &PgPool, max_depth: u32) -> Result<bool> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM queue_service_probes WHERE claimed_until IS NULL",
    )
```

Backpressure only monitors `queue_service_probes` (unclaimed items). It does NOT monitor `queue_host_scans`.

**Impact:** The host_scans queue can accumulate thousands of unclaimed items while backpressure is inactive. With 1348 ranges × average ~100 alive hosts = ~135k hosts queued, but deepscan only processes them at masscan speed.

### Issue #6: Masscan temp files not cleaned up on error

**File:** `src/masscan.rs:52-55`

```rust
let _ = std::fs::remove_file(&targets_file);
// ... masscan runs ...
let _ = std::fs::remove_file(&output_file);
```

If masscan crashes or the process is killed between writing the targets file and the cleanup, the temp files remain in `/tmp/`. The cleanup on line 52 only removes the targets file AFTER masscan has already run (not before error handling).

Actually looking more carefully: the targets file IS cleaned up on line 52 after masscan runs. But if the Rust process is killed (e.g., OOM), temp files in `/tmp/masscan_*` will persist.

**Impact:** Minor — temp files in /tmp accumulate on process crashes. Low risk in Docker (container restart cleans /tmp).

### Issue #7: Error in masscan silently swallowed

**File:** `src/main.rs:182-184`

```rust
.unwrap_or(Ok(vec![]))   // masscan error → empty vec
.unwrap_or_default();     // serde error → empty vec
```

If masscan fails entirely (e.g., not installed, permission denied), the error is silently converted to an empty result. No log, no alert.

**Impact:** Silent failure of the entire sweep stage. The sweep would loop forever, "finding" zero hosts, with no error in logs.

### Issue #8: `insert_host_scan` uses ON CONFLICT DO NOTHING

**File:** `src/queue.rs:163-168`

```rust
sqlx::query("INSERT INTO queue_host_scans (ip) VALUES ($1::inet) ON CONFLICT (ip) DO NOTHING")
```

Duplicate IPs are silently dropped. This is correct for idempotency, but means:
- If a host was already scanned and deepscanned, re-sweeping it does nothing
- The sweep has no way to force a re-scan of previously discovered hosts

**Impact:** Correct behavior for initial scan, but no mechanism for periodic re-scanning of known hosts.

### Issue #9: Discovery ports include unusual services

**File:** `scanerr.toml:6`

```
discovery_ports = [80, 443, 7547, 554, 22, 53, 8080, 179, 2000, 123, 23, 81, 1883, 5000, 8000, 8001, 8002, 8081, 8888, 37777]
```

Notable ports:
- **7547** — TR-069/CWMP (ISP router management, commonly exploited)
- **554** — RTSP (IP cameras)
- **179** — BGP (internet infrastructure)
- **2000** — MikroTik bandwidth-test
- **123** — NTP
- **23** — Telnet (insecure)
- **1883** — MQTT (IoT)
- **37777** — Dahua camera/ DVR proprietary port

**Impact:** Good coverage. The mix of common (80/443/22) and specialized (7547/554/37777) ports balances breadth with target specificity.

---

## Recommendations

### Priority 1: Implement sweep_chunk_size and sweep_interval_secs

Use the existing config fields:
1. Batch `sweep_chunk_size` ranges per masscan invocation (e.g., 20 ranges → 1 masscan call)
2. Add `tokio::time::sleep(Duration::from_secs(sweep_interval_secs))` at end of cycle

This would reduce masscan invocations from 1348 to ~68 per cycle, and add a configurable cooldown.

### Priority 2: Add error logging for masscan failures

Replace `unwrap_or(Ok(vec![]))` with proper error logging:
```rust
match masscan::run_stage1_batch(&[range_clone], &ports_clone, rate) {
    Ok(results) => { /* insert hosts */ }
    Err(e) => tracing::error!("masscan failed for {}: {}", range, e),
}
```

### Priority 3: Add backpressure for host_scans queue

Check `queue_host_scans` depth alongside `queue_service_probes`:
```rust
let host_depth = sqlx::query_as("SELECT COUNT(*)::bigint FROM queue_host_scans WHERE claimed_until IS NULL");
let probe_depth = sqlx::query_as("SELECT COUNT(*)::bigint FROM queue_service_probes WHERE claimed_until IS NULL");
// pause if either exceeds threshold
```

### Priority 4: Parallel range scanning

Use `tokio::task::spawn_blocking` with a semaphore to scan N ranges concurrently (e.g., 4 at a time). This would reduce cycle time from ~22.5 hours to ~5.6 hours.

---

## Range Statistics

- **Total ranges:** 1348
- **CIDR distribution:** mostly /22 and /24, some /16, /17, /18, /19, /20, /21, /23
- **Geographic focus:** Primarily Bulgarian IP space (2.x, 5.x, 31.x, 37.x, 45.x, 46.x, 62.x, 77.x, 78.x, 79.x, 80.x, 81.x, 82.x, 83.x, 84.x, 85.x, 87.x, 88.x, 89.x, 90.x, 91.x, 92.x, 93.x, 94.x, 95.x, 109.x, 151.x, 176.x, 178.x, 185.x, 188.x, 192.x, 193.x, 194.x, 195.x, 212.x, 213.x, 217.x)
- **Estimated total IP space:** ~1.5M addresses (sum of all CIDR ranges)
