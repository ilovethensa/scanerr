# scanerr — Coordination Report for Agents

**Date:** 2026-08-28 18:07
**Prepared by:** analysis agent
**Status:** Investigation complete; ready for implementation hand-off

This report consolidates the reliability investigation. It supersedes the earlier
`reliability-investigation.md` where findings were speculative. Everything below is
**verified against the live VM** (`root@192.168.1.202`) and the current source.

---

## TL;DR — who owns what

| Task | Owner | File | Status |
|------|-------|------|--------|
| Probe timeout budget (25% `unknown`) | analysis agent | `.agents/probe-analysis.md` | Analyzed, not coded |
| Deepscan OOM (UNBOUNDED masscan concurrency) | deepscan-analysis agent | `.agents/deepscan-analysis.md` | Analyzed, not coded |
| `backfill()` full-table scan | Agent 1 | `.agents/task-board.md` | Analyzed |
| Claim query COALESCE index | Agent 2 | `.agents/task-board.md` | Analyzed |
| Enrich retry on failure | Agent 4 | `.agents/task-board.md` | Analyzed |

**No source code has been changed.** All work so far is analysis + notes.

---

## Production snapshot (live, 2026-08-28)

```
hosts = 7978   services = 13108
queue depths:   host_scans = 1523   service_probes = 0   enrichments = 0
service kinds:  http 5430 | UNKNOWN 3277 (25%) | ssh 2103 | ftp 967 | pop3 500
               imap 441 | mikrotik 347 | mysql 22 | tls 8 | telnet 4 | smtp 4
               pptp 3 | rtsp 2
dmesg:         masscan + scanerr OOM-killed by cgroup (historical)
docker stats:  deepscan RSS 16–111 MiB / 512 MiB (low right after restart)
```

**Read this:** the probe stage is idle (queue empty). The deepscan stage is the bottleneck
(1523-host backlog). 25% of all stored services are `unknown` — that is a probe-correctness
problem, not a throughput problem.

---

## FINDING 1 — Probe timeout budget (real defect, not batch size)

**Verified root cause:**
- `run_probe` wraps the entire `probe()` in a **5s** outer timeout (`scanerr.toml:29`,
  `main.rs:303`).
- But `probe()` → `dispatch()` → `read_banner()` alone is **3s connect + 5s read = up to 8s**,
  then `try_http_fallback()` adds **3×5s** (HTTP + HTTPS + raw TLS) (`engine.rs:239,262`).
- For any non-banner port (a normal HTTP server sends NO greeting), the 5s cap fires *during
  `read_banner`*, so the probe is dropped (timeout) or misclassified `unknown`.
- **Evidence:** 1,148 of 3,277 `unknown` services sit on web ports (80/443/8080/8000/8443/8888/
  81/5000/9000…) — 35% of all unknown. They should almost all be http/https.

**Earlier draft was WRONG:** the original Agent-3 task ("reduce claim batch from 10", "add a
connect timeout") misses the cause. Tasks run concurrently (queue empty) and a connect timeout
already exists (3s). Do not implement that.

**Fix (see `.agents/probe-analysis.md`):**
1. Lower `read_banner` to 2s connect + 2s read (`engine.rs:240,252`).
2. Remove the tight 5s blanket outer timeout; rely on per-phase timeouts + a ~20s safety cap.
3. Verify `test-probe 1.1.1.1:80` / `:443` → http/https; deploy and watch `unknown` share fall.

---

## FINDING 2 — Deepscan OOM = UNBOUNDED masscan concurrency (real root cause)

**Verified root cause:**
- `run_deepscan` (`main.rs:233`) launches each host's masscan with
  `tokio::task::spawn_blocking(move || { … })` and **never awaits the JoinHandle**.
- The `loop` then immediately re-claims the next host and spawns another. So one replica
  accumulates **unbounded concurrent masscan subprocesses** (only capped by tokio's blocking
  pool ~512). With 4 replicas this is exactly what `dmesg` shows OOM-killed.
- The historical "Fix deepscan OOM: batch=1 / 512MB" commits fixed the wrong thing — `claim_host_scans(pool, 1, …)` only limits rows per *claim query*, not in-flight tasks.

**⚠ Earlier draft was WRONG and DANGEROUS:** my first Agent-5 suggestion "raise deepscan replicas
4→8" would have made OOM *worse*. Do NOT raise replicas or `deep_scan_rate` until concurrency is
bounded.

**Fix (see `.agents/deepscan-analysis.md`):**
1. **Bound in-flight masscan per replica** — `tokio::sync::Semaphore` (~2 permits), or `.await`
   the JoinHandle to run sequentially. 4 replicas × 2 = 8 concurrent masscan max. Mandatory.
2. Add `sweep()` + `increment_attempts` to deepscan so OOM-crashed hosts get requeued/deleted
   (currently no sweep → orphaned hosts lost forever).
3. Add masscan `--wait 1` (default is 10s idle) → cuts per-host scan ~10x and shrinks peak memory.
4. (Optional) collapse `run_stage2` (masscan.rs:78) into `masscan_scan` — it's a duplicate.

**Verify:** `cargo check && cargo test`; deploy; `docker stats` RSS stays <512MB; `dmesg` shows no
new OOM; host_q drains to ~0.

---

## FINDING 3 — `backfill()` full-table scan (Agent 1)

- `normalize::backfill` (`src/normalize.rs:205`) runs `SELECT id, data FROM services` and loads
  ALL rows into memory on every sweep/deepscan start. Confirmed in prod logs: 1.3–8s slow queries.
  With deepscan OOM-cycling, it re-runs constantly. Idempotent — should run once.
- **Fix:** add a `meta` table + version marker; skip backfill when code version == stored version.
  (I started a `meta` migration but reverted it to avoid a half-wired change — Agent 1 should
  implement the whole thing.)

---

## FINDING 4 — Claim query COALESCE (Agent 2) & Enrich retry (Agent 4)

- Claim queries use `WHERE COALESCE(claimed_until, 0) < $2` (queue.rs:26,54,82). The index is a
  plain btree on `(claimed_until, id)`; the COALESCE wrapper likely prevents index usage on the
  empty-queue case (1.5s slow query noted). Verify with EXPLAIN; prefer
  `claimed_until IS NULL OR claimed_until < $2`.
- `run_enrich` deletes queue items on failure without retry/increment (main.rs:380-386). Acceptable
  for 404 favicons; network errors silently lost. Agent 4's call.

---

## DO NOT (avoid duplicate / harmful work)

- Do NOT raise deepscan `replicas` or `deep_scan_rate` — OOM trigger until concurrency is bounded.
- Do NOT "reduce probe claim batch from 10" — tasks are concurrent, queue is empty.
- Do NOT add a connect timeout to the probe engine — one already exists (3s).
- Do NOT re-run the `backfill` migration I reverted — Agent 1 owns that end-to-end.

---

## How to verify your fix against prod

```sh
# build + deploy
./deploy.sh
# watch for the slow backfill query disappearing
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose logs -f 2>&1 | grep -i 'slow statement'"
# queue depths
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose exec -T postgres psql -U scanerr -d scanerr -t -A -c \
  'SELECT (SELECT count(*) FROM queue_host_scans) AS host_q, (SELECT count(*) FROM queue_service_probes) AS probe_q'"
# unknown share
ssh root@192.168.1.202 "cd /opt/scanerr && docker compose exec -T postgres psql -U scanerr -d scanerr -t -A -c \
  \"SELECT count(*) FILTER (WHERE data->>'kind'='unknown') * 100 / count(*) FROM services\""
# OOM
ssh root@192.168.1.202 "dmesg | grep -i 'oom' | tail"
```

## Files written for coordination
- `.agents/REPORT.md` — this file
- `.agents/probe-analysis.md` — Finding 1 detail
- `.agents/deepscan-analysis.md` — Finding 2 detail
- `.agents/task-board.md` — ownership + task list (Agent 1/2/3/4/5)
- `.agents/reliability-investigation.md` — earlier speculative notes (superseded; keep for history)
