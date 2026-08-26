# TODO

## Fix TLS Fingerprinting (JA3) Rejections

Some network devices (TP-Link routers, certain cameras/NVRs) perform TLS fingerprinting and reject connections from non-browser TLS stacks. reqwest/rustls produces a JA3 fingerprint that these devices don't recognize, causing HTTP 400 or connection resets even when curl works fine.

### Affected Modules

- `src/probe/http/mod.rs` — HTTP/HTTPS probe: uses reqwest with rustls. Devices that fingerprint JA3 reject the TLS ClientHello before any HTTP data is exchanged. The probe gets 400 or empty responses.
- `src/probe/tls.rs` — TLS cert extraction: also uses tokio-rustls. Same fingerprint issue when connecting to picky TLS servers.
- `src/probe/engine.rs` — `try_http_fallback()`: calls the HTTP probe, so any device doing JA3 checking will fail the entire fallback chain.
- `src/probe/dispatch.rs` — `probe()`: depends on the above probes succeeding. Silent failures result in `kind: "unknown"` in the database.

### Known Impacted Targets

- TP-Link Archer AX80v1 (`78.159.150.73:443`) — returns 400 to scanner, 200 to curl
- Possibly other Chinese network device web UIs doing TLS fingerprinting

### Potential Fixes

1. **Use native-tls instead of rustls** — native-tls uses the system's OpenSSL/SChannel which has a more "normal" JA3 fingerprint. Tradeoff: loses cross-platform consistency and `danger_accept_invalid_certs` behavior changes.
2. **Use rustls with a browser-like config** — configure cipher suites, ALPN, and extensions to mimic Chrome's JA3. Partially effective; fingerprinting is increasingly sophisticated.
3. **Use curl as a fallback** — if reqwest fails with 400/empty on HTTPS, shell out to curl as a second attempt. Simple but adds a dependency and is slower.
4. **Accept the limitation** — these are edge cases on specific consumer devices. The vast majority of HTTP services don't fingerprint TLS. Document and move on.

### Current Workaround

None. The scanner silently fails and stores `{"kind": "unknown"}` for these targets. The dispatch error logging added in `dispatch.rs` will now surface these failures as warnings.
