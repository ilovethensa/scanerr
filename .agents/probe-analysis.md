# Probe System Analysis — Agent Notes

**Date:** 2026-08-28
**Author:** analysis agent
**Scope:** `src/probe/engine.rs`, `src/probe/dispatch.rs`, `src/main.rs` (`run_probe`), `scanerr.toml`

## How the probe pipeline actually works

1. `run_probe` (main.rs:265) claims up to 10 service-probes, spawns one tokio task per item.
2. Each task: `tokio::time::timeout(probe_timeout, probe::dispatch::probe(...))` — `probe_timeout = config.probe.timeout_secs = 5s` (main.rs:303, scanerr.toml:29).
3. `probe()` (dispatch.rs:19) calls `registry.dispatch()` then `ensure_host`, rndns (no-op), geoip, asn.
4. `ProbeRegistry::dispatch` (engine.rs:159):
   - HTTPS ports (443/8443): skip banner, go to fallback.
   - Other ports: `read_banner` = **3s connect + 5s read** (engine.rs:239-260).
   - Banner match → active probe (fast path, works great).
   - No banner → `try_http_fallback` = HTTP (5s) → HTTPS (5s) → raw TLS (5s) (engine.rs:262-296).
   - Still nothing → active-only probes (PPTP/MQTT/SCCP) → else `ServiceData::default()` (kind=`unknown`).

## ROOT CAUSE (corrects earlier Agent-3 task)

**The 5s outer timeout is far too tight for the internal timeout budget.**

Worst-case for a non-banner port (a normal HTTP server sends NO greeting):
- `read_banner`: 3s connect + 5s read = **up to 8s** before `try_http_fallback` even runs.
- The outer 5s `timeout` (main.rs:303) fires **during `read_banner`**, cancelling the future.
- Result: the probe is `complete()`d and the service is **dropped entirely** (timeout, not stored) OR, when it squeaks in under 5s, falls through to `unknown`.

This is why the unknown rate is high and clustered on web ports (see below). The earlier
Agent-3 framing ("reduce batch size / add connect-level timeouts") does **not** address this —
batching is fine (tasks run concurrently) and connect already has a 3s timeout. The real fix is
time-budget alignment.

### Evidence from production (2026-08-28, live DB)
- Services total: **13,108**; hosts: **7,978**.
- Kind distribution: http 5430, **unknown 3277 (25%)**, ssh 2103, ftp 967, pop3 500, imap 441,
  mikrotik 347, mysql 22, tls 8, telnet 4, smtp 4, pptp 3, rtsp 2.
- **1,148 unknown services sit on web ports** (80,443,8080,8000,8443,8888,81,8081,8001,8002,
  5000,9000,3000,8088) = 35% of all unknown. These should overwhelmingly be HTTP/HTTPS.
  This is consistent with the fallback being killed by the 5s cap.
- Probe queue depth: **0** (probe stage is NOT the bottleneck right now — it is over-provisioned
  at 4 replicas).
- Host-scan queue depth: **1,523** → **deepscan is the bottleneck** (see separate issue below).

## RECOMMENDED FIX (Task: "probe timeout budget") — owned by this agent

Do NOT just bump `timeout_secs`. Restructure so per-phase timeouts are independent and the outer
cap is realistic:

Option A (minimal, safe):
- Reduce `read_banner` to **2s connect + 2s read** (engine.rs:240,252).
- Keep per-fallback 5s but cap the whole `probe()` outer timeout at ~**15s** (config default 5 → 15),
  OR remove the blanket outer timeout and rely on internal phase timeouts (each phase already has
  one, so nothing can hang) with a 20s safety net.
- Verify: known HTTP-on-weird-port hosts (e.g. 1.1.1.1:80, :8080) now classify as http, not unknown.

Option B (better long-term):
- Split budget: connect ≤2s, first-line read ≤2s, then HTTP/HTTPS each ≤5s with a shared
  `tokio::time::timeout` budget passed down, so a slow host can't eat the whole allowance.

**Verify after fix:** `cargo check && cargo test`, then `./target/debug/scanerr test-probe
1.1.1.1:80` and `:443` return kind=http/https; deploy and watch `unknown` share drop and
`SELECT ... kind='unknown' AND port IN (...)` count decrease.

## SECONDARY FINDINGS

### Deepscan is the real pipeline bottleneck (not probe)
- host_q = 1523 backlog; deepscan replicas=4 @ 512MB.
- **Root cause of the deepscan OOMs is UNBOUNDED masscan concurrency** (run_deepscan spawns each
  host's masscan via `spawn_blocking` WITHOUT awaiting, then re-claims immediately → one replica
  runs hundreds of concurrent masscan subprocesses → `dmesg` cgroup OOM kills). The "batch=1/512MB"
  fixes were the wrong knob. **Do NOT raise replicas or deep_scan_rate** until concurrency is
  bounded. Full analysis + fix plan in `.agents/deepscan-analysis.md` (Agent 5, owned by
  deepscan-analysis agent): bound in-flight masscan with a Semaphore (~2/replica), add `sweep()` to
  requeue crashed hosts, add masscan `--wait 1` to cut per-host scan ~10x.

### backfill() full-table scan (Issue #1) — owned by Agent 1, NOT this agent
- `normalize::backfill` (src/normalize.rs:205) does `SELECT id, data FROM services` and loads
  ALL rows into memory on every sweep/deepscan start. Confirmed in prod logs: slow query 1.3–8s.
  With deepscan OOM-cycling, this re-runs constantly. I reverted my stray `meta` migration; Agent 1
  should add a version marker so it runs once. Left as-is for Agent 1.

### Enrichment drops on failure (Issue #5) — owned by Agent 4
- run_enrich (main.rs:380) deletes queue item on error without retry/incrementing attempts.
  Confirmed. Acceptable for 404 favicons; network errors silently lost. Agent 4's call.

## What NOT to do (avoid duplicate/wasted work)
- Do not "reduce probe claim batch from 10" — tasks run concurrently; batch size is not the
  throughput limiter (queue is empty). The earlier Agent-3 rationale is incorrect.
- Do not add a connect timeout to engine.rs — it already has one (3s).
- Do not touch probe throughput via more replicas — probe queue is empty; add deepscan replicas
  or memory instead.
