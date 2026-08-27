# scanerr Fingerprint System — Design Report

## Overview

scanerr identifies network services by matching observed data (HTTP headers, TLS certs, SSH banners, etc.) against a corpus of YAML signature files. Each signature describes a product — nginx, WordPress, Hikvision cameras, etc. — through a set of field matchers with individual confidence weights.

The system has three layers:

1. **Evidence** — a normalized flat map of `field_key → [values]` built from probe results
2. **Signatures** — YAML files defining what to match and how strongly each match matters
3. **Scoring** — evaluates every signature against the evidence and picks the best one

---

## Signature Format

Each YAML file defines one product:

```yaml
id: hikvision            # unique slug, used as the canonical identifier
name: Hikvision          # human-readable name, written to DB as `product`
category: camera         # grouping hint (camera, webapp, vpn, etc.)
tags: [camera, surveillance, iot]  # merged into the service's tag list
priority: 90             # tiebreaker when scores are equal (higher wins)
condition: any           # "any" or "all" — see below
matchers:                # list of field matchers
  - field: http.body
    op: contains
    value: multiVideoActiveX
    weight: 8
```

### Fields

**Top-level:**

| Field | Required | Description |
|-------|----------|-------------|
| `id` | yes | Unique slug. Must match the filename (without `.yaml`). |
| `name` | yes | Display name written to `product` on match. |
| `category` | no | Grouping label (e.g. `webapp`, `camera`, `vpn`). |
| `tags` | no | Tags merged into the service on match. |
| `priority` | no | Tiebreaker when two signatures have the same score. Default 50. |
| `condition` | no | `any` (default) or `all`. Controls how matchers combine. |
| `matchers` | yes | List of matcher definitions. |

**Matcher definition:**

| Field | Required | Description |
|-------|----------|-------------|
| `field` | yes | Evidence key to look up (see "Available Fields" below). |
| `op` | yes | Comparison operator. |
| `value` | yes | Value to compare against. |
| `weight` | no | Confidence contribution of this matcher. Default 1. |

### Operators

| Operator | Behavior |
|----------|----------|
| `contains` | Value contains the substring (case-sensitive). |
| `icontains` | Value contains the substring (case-insensitive). |
| `equals` | Value matches exactly. |
| `startswith` | Value starts with the substring. |
| `endswith` | Value ends with the substring. |
| `regex` | Value matches the Rust regex. |
| `hash_equals` | SHA-256 of the value (first 8 bytes as i64) equals the numeric value. Used for favicon hashes. |
| `exists` | Field has any value at all (ignores `value`). |

### Condition

- **`any`** (default): At least one matcher must hit. Confidence is driven by the strongest single match.
- **`all`**: Every matcher must hit. Confidence is the ratio of total matched weight to total weight across all matchers.

Most signatures use `any`. Use `all` when you need to confirm multiple properties simultaneously (e.g. "title contains X AND server is Y").

---

## Available Fields

The evidence layer normalizes `ServiceData` into a flat map. These are the field keys matchers can reference:

### Common

| Field | Example |
|-------|---------|
| `kind` | `http`, `ssh`, `ftp`, `unknown` |
| `port` | `443` |
| `product` | `nginx` (set by a previous probe stage) |
| `version` | `1.18.0` |
| `banner` | Full banner string |
| `tags` | Any existing tags |

### HTTP

| Field | Example |
|-------|---------|
| `http.status` | `200` |
| `http.title` | `Dashboard - Grafana` |
| `http.body` | Full HTML body |
| `http.server` | `nginx/1.18.0` |
| `http.host` | `example.com` |
| `http.rdns` | Reverse DNS |
| `http.waf` | WAF detection |
| `http.favicon_hash` | mmh3 hash of favicon |
| `http.html_hash` | SHA-256 of body content |
| `http.robots` | robots.txt content |
| `http.securitytxt` | security.txt content |
| `http.tags` | HTTP-specific tags |
| `http.header.{name}` | Any response header (lowercase key). E.g. `http.header.server`, `http.header.www-authenticate` |

### SSL/TLS

| Field | Example |
|-------|---------|
| `ssl.subject_cn` | Common Name from certificate |
| `ssl.issuer_cn` | Issuer CN |
| `ssl.self_signed` | `"true"` if self-signed |

### SSH

| Field | Example |
|-------|---------|
| `ssh.raw` | Full SSH banner |
| `ssh.key_type` | `ssh-rsa` |
| `ssh.fingerprint` | Host key fingerprint |
| `ssh.product` | Detected SSH implementation |
| `ssh.version` | SSH version string |

### FTP

| Field | Example |
|-------|---------|
| `ftp.system` | SYST response |
| `ftp.features` | FEAT entries |
| `ftp.commands` | Supported commands |
| `ftp.anonymous_listing` | Anonymous FTP listing |

### SMTP

| Field | Example |
|-------|---------|
| `smtp.starttls` | `"true"` if STARTTLS supported |
| `smtp.ehlo` | EHLO extension strings |

### MQTT

| Field | Example |
|-------|---------|
| `mqtt.version` | Protocol version |
| `mqtt.return_code` | CONNACK return code |
| `mqtt.subscriptions` | Discovered topics |

---

## Scoring and Confidence

Confidence is a percentage (0–100) representing how certain the system is that a signature matches.

### For `condition: any`

Confidence = `(best_matching_weight / max_weight_in_signature) × 100`

Only the strongest single match matters. If a signature has 8 matchers but only one hits, that one matcher's weight relative to the max weight in the signature determines confidence.

**Example:**
- Signature has matchers with weights [5, 8, 6, 5, 9, 8, 25, 5]
- The weight-25 matcher hits
- Confidence = 25/25 = **100%**

**Example:**
- Same signature, but only the weight-8 matcher hits
- Confidence = 8/25 = **32%**

This means: a single definitive signal (brand name in a header, exact product string) can drive confidence to 100% on its own. Weak or ambiguous signals produce proportionally lower confidence.

### For `condition: all`

Confidence = `(total_matched_weight / total_weight_of_all_matchers) × 100`

All matchers contribute. This is a coverage metric — how much of the expected evidence was found.

### Tiebreaking

When two signatures have the same score, the one with higher `priority` wins. Priority is set per-signature and is independent of matcher weights.

---

## Weight Guidelines

Weights represent how **definitive** a single matcher is for identifying the product. Not how common the signal is — how much certainty it provides when it appears.

| Weight | Meaning | Examples |
|--------|---------|---------|
| 1–3 | Weak / ambiguous. Could appear in many products. | Generic CSS classes, common JS libraries |
| 4–6 | Moderate. Suggestive but not conclusive. | Common headers (`Server: nginx`), generic page structures |
| 7–9 | Strong. Rare enough to be highly indicative. | Product-specific strings (`wp-content`), unique HTML patterns |
| 10–15 | Very strong. Nearly unique to this product. | Brand names in headers, product-specific API paths |
| 20+ | Definitive. The product is literally identifying itself. | `www-authenticate: Basic realm="TP-LINK"`, certificate CN |

**Key principle:** A matcher's weight should reflect its **discriminative power**, not how often you expect to see it. A brand name appearing in a Basic auth realm is100% conclusive — weight it accordingly.

---

## Writing Signatures — Process

1. **Probe the target.** Use `scanerr test-probe <ip>:<port>` to get the raw service data.
2. **Find the strongest signals.** Look for product-specific strings in headers, body, certs, or banners. The more unique to one product, the higher the weight.
3. **Write matchers from strongest to weakest.** Start with the most definitive signal, add supporting signals for coverage.
4. **Set weights based on discriminative power.** A string that only appears in one product gets high weight. A generic string gets low weight.
5. **Test.** Rebuild and run `test-probe` against the target. Check that `product` and `confidence` are correct.
6. **Test against similar products.** Make sure the signature doesn't false-positive on related products.

---

## Known Issues and Open Questions

### 1. Confidence is per-signature, not per-matcher

The current system picks the single best-matching signature and reports its confidence. If two signatures partially match the same service (e.g. "nginx" and "WordPress on nginx"), only the winner's confidence is reported. The loser's partial match is invisible.

**Question:** Should we report the top N matches, or a primary + secondary identification?

### 2. No version extraction

Most signatures identify the product but not the version. The evidence layer has `http.server` (which often contains `nginx/1.18.0`) but there's no standardized way to extract version strings from matchers.

**Question:** Should we add a `version_extractor` field to matchers (e.g. regex capture group), or keep it simple and rely on the probe to parse versions?

### 3. Weight scale is arbitrary

Weights are positive integers with no defined maximum. In practice they range from 1 to 25, but there's no formal scale. This makes it hard for new contributors to choose appropriate values.

**Question:** Should we formalize the weight scale (e.g. 1–10, with documented meaning per level)?

### 4. `condition: all` confidence can be gamed

If a signature has 3 matchers with weights [1, 1, 1] and all hit, confidence is 100%. But each individual matcher is weak. The "all" condition assumes every matcher is equally important, which isn't always true.

**Question:** Should `all` condition support per-matcher minimum thresholds, or is the current behavior acceptable?

### 5. No negative matchers

There's no way to say "match if X is present AND Y is absent." For example, "matches nginx but only if it's NOT openresty." This requires either multiple signatures or external logic.

**Question:** Is this a real need, or do separate signatures handle it adequately?

### 6. Regex performance

The `regex` operator compiles patterns at startup, but complex regexes against large HTTP bodies could be slow in the hot path. There's no timeout or complexity limit on regex patterns.

**Question:** Should we add a regex complexity budget or a per-match timeout?

### 7. Multi-field header matching

HTTP headers are flattened to `http.header.{key}`. This works for single-value headers, but some headers (like `Set-Cookie`) appear multiple times. The current system stores them as multiple values under the same key, which `contains`/`icontains` handle correctly. But there's no way to match "header X appears exactly N times."

**Question:** Is frequency-based matching needed, or is presence/absence sufficient?

### 8. Signature versioning

There's no version field in signatures. When a product changes its identifying strings (e.g. WordPress removes `wp-content` in a future version), the signature silently breaks. There's no way to mark a signature as "valid for versions X–Y."

**Question:** Should signatures have optional `valid_from`/`valid_until` fields, or is manual curation sufficient?

---

## File Organization

```
signatures/
├── http/           # HTTP service signatures
│   ├── camera/     # IP cameras, NVRs
│   ├── cdn/        # CDN providers
│   ├── framework/  # JS frameworks
│   ├── iot/        # IoT devices
│   ├── mail/       # Mail servers
│   ├── media/      # Media servers
│   ├── monitoring/ # Monitoring tools
│   ├── networking/ # Routers, switches
│   ├── power/      # Power infrastructure
│   ├── servers/    # Web servers
│   ├── vpn/        # VPN concentrators
│   └── webapp/     # Web applications
└── ssl/            # TLS certificate signatures
```

Organize by protocol first, then by category. The directory structure is for human readability — the loader recursively finds all `.yaml` files regardless of path.

---

## Example Signatures

### Simple — single strong matcher

```yaml
id: wazuh
name: Wazuh
category: monitoring
tags: [security, siem]
priority: 80
matchers:
  - field: http.title
    op: icontains
    value: Wazuh
    weight: 5
```

### Multiple matchers — progressive confidence

```yaml
id: tplink-router
name: TP-Link Router
category: networking
tags: [router, networking, iot]
priority: 85
condition: any
matchers:
  - field: http.header.www-authenticate
    op: contains
    value: TP-LINK
    weight: 25          # definitive — the device identifies itself
  - field: http.body
    op: contains
    value: tplinklogin.net
    weight: 9           # strong — unique TP-Link domain
  - field: http.body
    op: contains
    value: tplinkwifi.net
    weight: 8           # strong — unique TP-Link domain
  - field: http.body
    op: contains
    value: tpEncrypt.new.js
    weight: 8           # strong — TP-Link-specific JS
  - field: http.body
    op: contains
    value: AX80v1
    weight: 2           # weak — model string, low discriminative power
  - field: http.header.server
    op: equals
    value: Router Webserver
    weight: 2           # weak — generic server string
```

### Header-based identification

```yaml
id: plex
name: Plex Media Server
category: media
tags: [media, streaming]
priority: 85
matchers:
  - field: http.header.x-plex-protocol
    op: exists
    value: "1"
    weight: 5
```

### SSL certificate identification

```yaml
id: kubernetes-ingress-controller
name: Kubernetes Ingress Controller
category: infrastructure
tags: [kubernetes, k8s, ingress, nginx]
priority: 40
matchers:
  - field: ssl.subject_cn
    op: contains
    value: Kubernetes Ingress Controller Fake Certificate
    weight: 5
```
