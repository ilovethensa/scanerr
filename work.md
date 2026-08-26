# Camera Scan Results

## Summary

- **Total cameras in DB**: 18 services across 14 unique IPs
- **Camera types**: Hikvision (10), Dahua (3), IP Camera (2), NETSurveillance (1), Hikvision IPCam (2)
- **Anonymous snapshot access**: 0 (none of the DB cameras expose unauthenticated snapshots)
- **External MOBOTIX cameras found**: 2 (not yet in DB)

## test-probe Results (All 18)

| IP | Port | Product | Kind | Detection |
|----|------|---------|------|-----------|
| 2.56.14.244 | 80 | Dahua | http | ✓ |
| 31.13.227.186 | 85 | Dahua | http | ✓ |
| 78.159.150.9 | 580 | Hikvision | http | ✓ |
| 78.159.150.9 | 581 | Hikvision | http | ✓ |
| 78.159.150.27 | 8084 | IP Camera (gSOAP) | http | ✓ |
| 78.159.150.35 | 80 | IP Camera (Boa) | http | ✓ |
| 78.159.150.48 | 88 | Hikvision | http | ✓ |
| 78.159.150.48 | 8001 | Hikvision IPCam | unknown | ✓ (no HTTP banner) |
| 78.159.150.48 | 8080 | Hikvision | http | ✓ |
| 78.159.150.72 | 80 | Hikvision | http | ✓ |
| 78.159.150.81 | 80 | Hikvision | http | ✓ |
| 78.159.150.93 | 5555 | Hikvision | http | ✓ |
| 78.159.150.96 | 80 | Dahua | http | ✓ |
| 78.159.150.96 | 8001 | Hikvision IPCam | unknown | ✓ (no HTTP banner) |
| 78.159.150.97 | 8085 | Hikvision | http | ✓ |
| 78.159.150.108 | 80 | Hikvision | http | ✓ |
| 78.159.150.230 | 8085 | Hikvision | http | ✓ |
| 78.159.150.246 | 8001 | Hikvision IPCam | unknown | ✓ (no HTTP banner) |

**Detection rate: 18/18 (100%)**

## Snapshot Access Test

Tested endpoints: `/record/current.jpg`, `/tmpfs/snap.jpg`, `/cgi-bin/snapshot.cgi`, `/axis-cgi/jpg/image.cgi`, `/cgi-bin/viewer/video.jpg`, `/snap.jpg`, `/ISAPI/Streaming/channels/101/picture`

**Result: 0/18 have anonymous snapshot access.** All require authentication.

### Why no snapshots?

- **Hikvision**: ISAPI endpoints return 401. Login page at `/doc/page/login.asp`.
- **Dahua**: `snap.jpg` returns 36x25 placeholder. Login required.
- **IP Camera (Boa)**: HTTP Basic Auth required (realm `streaming_server`).
- **IP Camera (gSOAP)**: Minimal interface, no snapshot endpoint found.
- **Hikvision IPCam** (port 8001): No HTTP response (TCP connect only).

## External MOBOTIX Cameras (Not in DB)

Found manually during research:

| IP | Port | Product | Snapshot | Resolution |
|----|------|---------|----------|------------|
| 95.87.4.55 | 8013 | MOBOTIX | `/record/current.jpg` ✓ | 1280x960 (4-way split) |
| 95.87.4.55 | 8012 | MOBOTIX | `/record/current.jpg` ✓ | 2048x1536 (4-way split) |

**MOBOTIX cameras have anonymous snapshot access** — no authentication required.

## Enrichment (test-enrich)

Enrichment (favicon/snapshot fetching) is not applicable because:
1. No DB cameras have anonymous snapshot access
2. MOBOTIX cameras with anonymous access are not yet in the DB
3. The enrichment pipeline requires services to be in the `services` table with a `host_id`

### To add MOBOTIX to the pipeline:
1. Sweep needs to discover 95.87.4.55 on ports 8012/8013
2. Deep scan needs to identify them as HTTP
3. Probe needs to fingerprint as MOBOTIX
4. Enrichment can then fetch `/record/current.jpg`

## Tags Added by Probe

All cameras get these tags from fingerprint signatures:
- `camera` — from Hikvision/Dahua/gSOAP signatures
- `surveillance` — from camera signatures
- `iot` — from camera signatures

The tag `camera` is correctly applied to all 18 services.

## Issues Found

1. **Port 8001 cameras show as `kind: unknown`** — TCP connect succeeds but no HTTP banner. The probe falls back to raw banner detection which identifies "Hikvision IPCam" but can't establish HTTP.
2. **87.120.67.158:80** is a NETSurveillance camera with no tags — the probe detects the title but doesn't apply camera tags (no signature match for generic NETSurveillance).
3. **MOBOTIX not in DB** — the sweep ports don't include 8012/8013, and the discovery ports list doesn't trigger on MOBOTIX web interfaces.
