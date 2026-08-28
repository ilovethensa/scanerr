use std::collections::BTreeSet;
use crate::models::ServiceData;

/// Normalize a ServiceData in place: canonical kind, product slug, category-only tags.
pub fn normalize_service(data: &mut ServiceData) {
    data.kind = canonical_kind(&data.kind).to_string();
    if let Some(ref p) = data.product {
        data.product = Some(canonical_product(p));
    }
    normalize_tags(data);
}

// ─── Kind ────────────────────────────────────────────────────────────────────

/// Map non-canonical kind strings to the canonical set.
/// Canonical kinds: http, ssh, ftp, smtp, imap, pop3, telnet, mysql, mqtt,
/// pptp, sccp, mikrotik, rtsp, bgp, tls, unknown
pub fn canonical_kind(kind: &str) -> &str {
    match kind {
        "https" => "http",
        "camera" => "http", // Hikvision ISAPI is HTTP
        other => other,
    }
}

/// Return a base category tag derived from the protocol kind.
fn kind_category(kind: &str) -> Option<&'static str> {
    match kind {
        "http" => Some("web"),
        "ssh" | "telnet" => Some("remote-access"),
        "ftp" => Some("file-transfer"),
        "smtp" | "imap" | "pop3" => Some("mail"),
        "mysql" => Some("database"),
        "mqtt" => Some("iot"),
        "pptp" => Some("vpn"),
        "sccp" => Some("voip"),
        "mikrotik" | "bgp" => Some("networking"),
        "rtsp" => Some("camera"),
        _ => None,
    }
}

// ─── Product ─────────────────────────────────────────────────────────────────

/// Canonical product slugs for known display names.
/// Anything not listed falls through to `slugify()`.
fn product_override(raw: &str) -> Option<&'static str> {
    match raw {
        "OpenSSH" => Some("openssh"),
        "nginx" => Some("nginx"),
        "Apache httpd" => Some("apache"),
        "Microsoft IIS" => Some("iis"),
        "LiteSpeed" => Some("litespeed"),
        "MikroTik" => Some("mikrotik"),
        "MikroTik RouterOS" => Some("mikrotik"),
        "MikroTik EQUINIX SO1 CORE" => Some("mikrotik"),
        "Hikvision" => Some("hikvision"),
        "Hikvision NVR/DVR" => Some("hikvision"),
        "Hikvision IPCam" => Some("hikvision"),
        "MariaDB" => Some("mariadb"),
        "MySQL" => Some("mysql"),
        "Google Web Server" => Some("gws"),
        "Amazon CloudFront" => Some("cloudfront"),
        "Nginx Proxy Manager" => Some("nginx-proxy-manager"),
        "UniFi OS" => Some("unifi-os"),
        "SIGPLUS" => Some("sigplus"),
        "XAMPP" => Some("xampp"),
        "Nextcloud" => Some("nextcloud"),
        "Pritunl" => Some("pritunl"),
        "BigBlueButton" => Some("bigbluebutton"),
        "MOBOTIX Camera" => Some("mobotix"),
        "Wazuh" => Some("wazuh"),
        "Cacti" => Some("cacti"),
        "Nagios" => Some("nagios"),
        "BGP" => Some("bgp"),
        "Cloudflare" => Some("cloudflare"),
        "Sucuri" => Some("sucuri"),
        _ => None,
    }
}

/// Produce a canonical lowercase product slug.
pub fn canonical_product(raw: &str) -> String {
    if let Some(canon) = product_override(raw) {
        return canon.to_string();
    }
    slugify(raw)
}

/// Lowercase, collapse whitespace to `-`, strip non-alphanumeric/hyphen chars,
/// collapse repeated hyphens, trim hyphens.
pub fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_was_dash = false;
    for c in s.chars().map(|c| c.to_ascii_lowercase()) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            prev_was_dash = false;
        } else if c == ' ' || c == '_' || c == '-' {
            if !prev_was_dash && !out.ends_with('-') {
                out.push('-');
                prev_was_dash = true;
            }
        }
        // other chars (/, ., (, etc.) silently dropped
    }
    // trim leading and trailing hyphens
    out.trim_matches('-').to_string()
}

// ─── Tags ────────────────────────────────────────────────────────────────────

/// Full allowlist of canonical category tags.
const ALLOWED_TAGS: &[&str] = &[
    "web", "mail", "camera", "surveillance", "iot", "networking", "vpn",
    "security", "monitoring", "remote-access", "file-transfer", "database", "voip",
    "erp", "cms", "cdn", "waf", "proxy", "storage", "cloud", "hosting",
    "self-hosted", "media", "streaming", "conferencing", "gaming", "rss",
    "analytics", "development", "framework", "php", "javascript",
    "government", "pki", "isp", "billing", "helpdesk", "ticketing",
    "dashboard", "api-gateway", "reverse-proxy", "discovery", "gps",
    "tracking", "fleet-management", "mesh", "power", "solar", "inverter",
    "smart-home", "home-assistant", "embedded", "accounting", "email",
    "control-panel", "router",
];

/// Map raw tag strings from probes/signatures to a canonical category tag.
/// Returns None for tags that should be dropped (products, vendors, protocol dupes, garbage).
fn canonical_tag(raw: &str) -> Option<String> {
    let lower = raw.to_lowercase();

    // Drop dynamic garbage tags
    if lower.starts_with("device:") || lower.starts_with("firmware:") {
        return None;
    }
    // Drop tags with non-ASCII or control characters (binary leak)
    if lower.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }

    // Aliases that map to a canonical category
    let alias = match lower.as_str() {
        // mail aliases
        "email" | "webmail" => "mail",
        // networking aliases
        "routing" | "routeros" => "networking",
        // power aliases
        "logger" => "power",
        // conferencing aliases
        "bigbluebutton" | "greenlight" => "conferencing",
        // gaming
        "minecraft" => "gaming",
        // cloud
        "aws" | "amazon" => "cloud",
        // media (nvr/dvr are hardware types, not categories)
        "video" => "media",
        // tracking
        "tracking" | "gps" | "fleet-management" => "tracking",

        // Product/vendor tags — drop (covered by product field)
        "nginx" | "openresty" | "hikvision" | "nvr" | "dvr" | "ubiquiti"
        | "unifi" | "mikrotik" | "dropbear" | "cisco" | "btest" => return None,

        // Already on the allowlist — pass through if valid
        other if ALLOWED_TAGS.contains(&other) => return Some(other.to_string()),
        _ => return None,
    };

    // Verify the alias target is in the allowlist
    if ALLOWED_TAGS.contains(&alias) {
        Some(alias.to_string())
    } else {
        None
    }
}

/// Rebuild `data.tags` to contain only canonical category tags.
///
/// Starts with the base category derived from `kind`, then merges
/// cleaned tags from probes/signatures, deduplicates case-insensitively,
/// and sorts.
fn normalize_tags(data: &mut ServiceData) {
    let kind = canonical_kind(&data.kind);
    let mut tags: BTreeSet<String> = BTreeSet::new();

    // 1. Base category from kind
    if let Some(cat) = kind_category(kind) {
        tags.insert(cat.to_string());
    }

    // 2. Clean existing tags
    for raw in &data.tags {
        if let Some(canonical) = canonical_tag(raw) {
            tags.insert(canonical);
        }
    }

    data.tags = tags.into_iter().collect();
}

// ─── Backfill ────────────────────────────────────────────────────────────────

/// Backfill all existing services in the database through normalize_service.
/// Idempotent — normalizing clean data is a no-op.
pub async fn backfill(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    use sqlx::Row;

    let rows: Vec<(i64, serde_json::Value)> = sqlx::query("SELECT id, data FROM services")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| (row.get::<i64, _>("id"), row.get::<serde_json::Value, _>("data")))
        .collect();

    let mut updated = 0u32;
    for (id, data_val) in &rows {
        let mut data: ServiceData = serde_json::from_value(data_val.clone())?;
        normalize_service(&mut data);
        let new_json = serde_json::to_value(&data)?;
        if *data_val != new_json {
            sqlx::query("UPDATE services SET data = $1 WHERE id = $2")
                .bind(&new_json)
                .bind(id)
                .execute(pool)
                .await?;
            updated += 1;
        }
    }

    if updated > 0 {
        tracing::info!("backfill: normalized {} services", updated);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_kind() {
        assert_eq!(canonical_kind("https"), "http");
        assert_eq!(canonical_kind("camera"), "http");
        assert_eq!(canonical_kind("http"), "http");
        assert_eq!(canonical_kind("ssh"), "ssh");
        assert_eq!(canonical_kind("unknown"), "unknown");
    }

    #[test]
    fn test_slugify() {
        assert_eq!(slugify("nginx"), "nginx");
        assert_eq!(slugify("Apache httpd"), "apache-httpd");
        assert_eq!(slugify("OpenSSH_9.2p1"), "openssh-92p1");
        assert_eq!(slugify("LiteSpeed"), "litespeed");
        assert_eq!(slugify("MikroTik RouterOS"), "mikrotik-routeros");
        assert_eq!(slugify("  nginx  "), "nginx");
    }

    #[test]
    fn test_canonical_product() {
        assert_eq!(canonical_product("nginx"), "nginx");
        assert_eq!(canonical_product("OpenSSH"), "openssh");
        assert_eq!(canonical_product("Apache httpd"), "apache");
        assert_eq!(canonical_product("Microsoft IIS"), "iis");
        assert_eq!(canonical_product("MikroTik"), "mikrotik");
        assert_eq!(canonical_product("Hikvision NVR/DVR"), "hikvision");
        assert_eq!(canonical_product("Unknown Software"), "unknown-software");
    }

    #[test]
    fn test_canonical_tag() {
        assert_eq!(canonical_tag("web"), Some("web".to_string()));
        assert_eq!(canonical_tag("mail"), Some("mail".to_string()));
        assert_eq!(canonical_tag("email"), Some("mail".to_string()));
        assert_eq!(canonical_tag("routing"), Some("networking".to_string()));
        assert_eq!(canonical_tag("nginx"), None); // product, not category
        assert_eq!(canonical_tag("hikvision"), None); // vendor
        assert_eq!(canonical_tag("btest"), None); // feature name
        assert_eq!(canonical_tag("device:123"), None); // dynamic garbage
        assert_eq!(canonical_tag("mikrotik"), None); // vendor
    }

    #[test]
    fn test_kind_category() {
        assert_eq!(kind_category("http"), Some("web"));
        assert_eq!(kind_category("ssh"), Some("remote-access"));
        assert_eq!(kind_category("smtp"), Some("mail"));
        assert_eq!(kind_category("ftp"), Some("file-transfer"));
        assert_eq!(kind_category("unknown"), None);
    }

    #[test]
    fn test_normalize_service() {
        let mut data = ServiceData {
            kind: "https".into(),
            product: Some("Apache httpd".into()),
            tags: vec!["nginx".into(), "mail".into(), "device:xyz".into(), "hikvision".into()],
            ..Default::default()
        };
        normalize_service(&mut data);
        assert_eq!(data.kind, "http");
        assert_eq!(data.product.as_deref(), Some("apache"));
        // Should contain: web (from http kind), mail (from existing tag)
        // Should NOT contain: nginx (product), device:xyz (garbage), hikvision (vendor)
        assert!(data.tags.contains(&"web".to_string()));
        assert!(data.tags.contains(&"mail".to_string()));
        assert!(!data.tags.contains(&"nginx".to_string()));
        assert!(!data.tags.contains(&"hikvision".to_string()));
        assert!(!data.tags.iter().any(|t| t.starts_with("device:")));
    }
}
