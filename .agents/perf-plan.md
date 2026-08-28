# Performance Implementation Plan — scanerr pipeline

**Date:** 2026-08-28
**Author:** analysis agent
**Goal:** Make each stage slightly faster than the one before it, WITHOUT ever making a stage
slower on purpose. Pipeline order: sweep → deepscan → probe → enrich → serve.

**Invariant to preserve on every deploy:** downstream_rate ≥ upstream_rate
  - deepscan(host/min) ≥ sweep(host/min)
  - probe(service_probe/min) ≥ deepscan(service_probe/min)
  - enrich(http_service/min) ≥ probe(http_service/min)

**Current measured baseline (post Task-1/Task-2 fix):** all queues tiny, ~17 hosts/min sweep,
~10–50 hosts/min deepscan, ~30 services/min probe, ~11.5/min enrich. No OOM (deepscan RSS ~210
MiB / 512 MiB, RestartCount=0).

**Key safety insight:** the biggest deepscan speedup is HOST BATCHING (one masscan over N IPs),
which keeps the masscan *process count* constant → OOM-safe (memory per masscan is ~constant).
Prefer batching over raising concurrency/rate. Keep `max_concurrent` ≤ 3/replica and verify RSS
stays < 450 MiB before going higher.

---

## Phase A — Deepscan: batch hosts per masscan (STAGE 2, biggest lever)
**Why first:** makes stage 2 far faster than stage 1; drains host_q; OOM-safe via batching.

Files:
- `src/masscan.rs`: generalize the per-IP scan into a batch scan.
  - Add `pub fn run_stage2_batch(targets: &[String], ports: &[u16], rate: u32) -> Result<Vec<ScanResult>>`
    that writes all targets (one per line) to the temp file and runs ONE masscan (`--wait 1`).
  - (Optionally) keep `run_stage2(ip)` as a thin wrapper `run_stage2_batch(&[ip], …)`.
- `src/main.rs` `run_deepscan`:
  - Claim a batch: `claim_host_scans(&pool, BATCH, t)` where `BATCH = 25` (tunable).
  - Build `ip_to_id: HashMap<&str, i64>` from claimed `(id, ip)`.
  - `results = masscan::run_stage2_batch(&ips, &ports, rate)`.
  - Group `results` by `ip`; for each ip-group:
      - if `group.len() as u32 > threshold` → `UPDATE hosts SET is_honeypot=true` (skip probes)
      - else `insert_service_probe` per port.
  - `complete()` every claimed id (on masscan error, still complete so sweep rediscovers).
  - Raise `max_concurrent` 2 → 3 per replica (12 total). Keep `--wait 1`.
- `scanerr.toml`: `deep_scan_rate = 3000` → `6000` (memory per masscan constant, OOM-safe; watch RSS).

Expected: ~25× host throughput at the same 8 concurrent masscan (one masscan now covers 25 IPs).
Deepscan becomes far faster than sweep → host_q drains to ~0.

Verify: `cargo check && cargo test`; deploy; `docker stats` deepscan RSS < 450 MiB; `dmesg|grep oom`
quiet; host_q trends to ~0; deepscan RestartCount stays 0.

---

## Phase B — Sweep: parallel + batched ranges (STAGE 1)
**Why second:** raises stage-1 rate, but deepscan (Phase A) is already >> sweep, so invariant holds.

Files:
- `src/main.rs` `run_sweep`:
  - Use existing `config.scanner.sweep_chunk_size` (default 20): accumulate that many ranges and
    call `masscan::run_stage1_batch(&chunk, …)` once (not one range per call).
  - Parallelize range chunks with `tokio::sync::Semaphore` (e.g. 4 permits) + `spawn_blocking`
    (mirrors the deepscan pattern; bounds masscan count).
  - Backpressure: also pause when `queue_host_scans` (not just `queue_service_probes`) is deep —
    add a `host_queue_depth` check using `COUNT(*) FROM queue_host_scans WHERE claimed_until IS NULL`.
    This is a SAFETY throttle so sweep never outruns deepscan unbounded (deepscan should normally
    stay ahead, so it rarely triggers).
- `scanerr.toml`: `discovery_rate = 1000` → `3000` (only 20 discovery ports; modest bandwidth).
  - Do NOT add `sweep_interval_secs` sleep here — that would make sweep slower (conflicts with the
    "never slower" rule). Leave it unused or implement only as an explicit opt-in politeness flag.

Expected: sweep host rate rises ~10–20× (chunking + parallelism). Deepscan (Phase A) still exceeds
it, so host_q stays drained.

Verify: queues stay balanced; host_q does not grow unbounded; no OOM.

---

## Phase C — Probe: cut per-probe overhead + more concurrency (STAGE 3)
**Why third:** deepscan (Phase A) now emits many more service_probes; probe must keep up.

Files:
- `src/probe/http/mod.rs`:
  - Reuse ONE `reqwest::Client` (module-level `once_cell::sync::Lazy<reqwest::Client>` built with the
    same options: user_agent, no redirect, 8s timeout, danger_accept_invalid_certs, http1_only).
    Removes client construction (~ms) per `probe_http` (called 2× per dispatch via fallback).
  - Remove the no-op `reverse_dns` (`lookup_host` just returns the IP) and `probe_by_hostname`;
    it is a wasted DNS round-trip + extra HTTP request per web service. (Keep `fetch_path`/
    `fetch_favicon_hash` — those are useful.) If hostname-based fingerprinting is desired, do it
    only when a real PTR exists (rndns placeholder currently returns None anyway).
- `src/probe/geoip.rs`:
  - Cache the MMDB readers process-wide: open `Reader` once per `db_path` (e.g. `Lazy<Option<Reader>>`
    or a small `GeoDb` cache). `lookup`/`lookup_asn` reuse the cached reader instead of
    `open_readfile` every call (currently 2 opens/probe).
- `src/main.rs` `run_probe`: raise claim batch `10` → `25` (probe is network-bound; more in-flight
  = more throughput). Keep the 20s outer safety cap.

Expected: removes ~5–15 ms + 1 DNS round-trip + 2 file-opens per probe; concurrency up → probe rate
scales with deepscan's larger output. Invariant: probe ≥ deepscan's service_probe output.

Verify: probe_q stays small; probe timeouts remain ~0; `services` count climbs faster.

---

## Phase D — Enrich: fewer round-trips + faster per item (STAGE 4)
**Why fourth:** enrich only handles http services; must keep up with probe's http output.

Files:
- `src/enrich/favicon.rs`:
  - Delete the unused `SELECT data FROM services` (lines 9–14, `let _data`) — 1 fewer DB round-trip.
  - Reuse ONE `reqwest::Client` (built per call today) — module-level Lazy, same options minus the
    unused bits.
  - Shorten `client.timeout` `10s` → `5s` (most favicons fast; 404s fail fast anyway).
- `src/main.rs` `run_enrich`: raise claim batch `10` → `25`.

Expected: ~3 fewer DB/network ops per favicon; enrich rate scales with probe's http output.
Invariant: enrich(http_service/min) ≥ probe(http_service/min).

Verify: enrich_q stays small; `service_assets` rows grow.

---

## Phase E (optional/politeness) — Serve
No change needed; axum is not throughput-bound.

---

## Rollout order & safety
Deploy ONE phase at a time, verify, then next. After each deploy confirm:
1. `docker stats` deepscan RSS < 450 MiB (never let it approach 512).
2. `dmesg | grep oom` shows NO new kills.
3. `docker inspect … --format 'restarts={{.RestartCount}}'` stays 0 for deepscan.
4. Queues: host_q ↓ (Phase A/B), probe_q ↓ (Phase C), enrich_q ↓ (Phase D). If any queue GROWS,
   the downstream stage for that queue is now slower than upstream → stop and fix before continuing
   (this would violate the invariant; do not ship a phase that grows a queue).

## What NOT to do
- Do NOT add `sweep_interval_secs` as a sleep (makes sweep slower — conflicts with the rule).
- Do NOT raise `max_concurrent` past 3/replica without first confirming RSS headroom.
- Do NOT raise `deep_scan_rate`/`discovery_rate` so high it triggers ISP rate-limiting; 3000/6000
  are conservative. Keep an eye on `sweep_interval_secs` only as an explicit politeness opt-in.
- Do NOT make probe outer timeout tighter again (Task 2 fixed the 95% timeout loss).
