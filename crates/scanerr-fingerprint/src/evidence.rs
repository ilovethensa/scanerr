use std::collections::BTreeMap;

use scanerr_protocol::models::ServiceData;

/// A normalized flat map of `field_key → [values]` used by the fingerprint
/// engine to match signatures.  Decouples the matcher from the shape of
/// `ServiceData`.
#[derive(Debug, Clone)]
pub struct Evidence(BTreeMap<String, Vec<String>>);

impl Evidence {
    /// Check whether the evidence contains a field key with any value matching
    /// `predicate`.
    pub fn matches_any<F: Fn(&str) -> bool>(&self, key: &str, pred: F) -> bool {
        self.0
            .get(key)
            .map(|vals| vals.iter().any(|v| pred(v)))
            .unwrap_or(false)
    }

    /// Get all values for a key.
    pub fn values(&self, key: &str) -> &[String] {
        self.0.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Iterate over all field keys.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(|s| s.as_str())
    }
}

impl From<&ServiceData> for Evidence {
    fn from(d: &ServiceData) -> Self {
        let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();

        // Common fields
        push(&mut m, "kind", &d.kind);
        if let Some(p) = d.port { push(&mut m, "port", &p.to_string()); }
        if let Some(ref v) = d.product { push(&mut m, "product", v); }
        if let Some(ref v) = d.version { push(&mut m, "version", v); }
        if let Some(ref v) = d.banner  { push(&mut m, "banner",  v); }
        for tag in &d.tags { push(&mut m, "tags", tag); }

        // HTTP
        if let Some(ref http) = d.http {
            push(&mut m, "http.status", &http.status.to_string());
            if let Some(ref v) = http.title  { push(&mut m, "http.title", v); }
            if let Some(ref v) = http.body   { push(&mut m, "http.body", v); }
            if let Some(ref v) = http.server { push(&mut m, "http.server", v); }
            if let Some(ref v) = http.host   { push(&mut m, "http.host", v); }
            if let Some(ref v) = http.rdns   { push(&mut m, "http.rdns", v); }
            if let Some(ref v) = http.waf    { push(&mut m, "http.waf", v); }
            if let Some(v) = http.favicon_hash { push(&mut m, "http.favicon_hash", &v.to_string()); }
            if let Some(v) = http.html_hash    { push(&mut m, "http.html_hash", &v.to_string()); }
            if let Some(ref v) = http.robots      { push(&mut m, "http.robots", v); }
            if let Some(ref v) = http.securitytxt { push(&mut m, "http.securitytxt", v); }
            for tag in &http.tags { push(&mut m, "http.tags", tag); }
            // Headers (lowercase keys, flattened)
            for (k, v) in &http.headers {
                let key = format!("http.header.{}", k.to_lowercase());
                match v {
                    serde_json::Value::String(s) => push(&mut m, &key, s),
                    serde_json::Value::Array(arr) => {
                        for item in arr {
                            if let Some(s) = item.as_str() { push(&mut m, &key, s); }
                        }
                    }
                    _ => {}
                }
            }
        }

        // SSL
        if let Some(ref ssl) = d.ssl {
            if let Some(ref v) = ssl.subject_cn { push(&mut m, "ssl.subject_cn", v); }
            if let Some(ref v) = ssl.issuer_cn  { push(&mut m, "ssl.issuer_cn", v); }
            if ssl.self_signed { push(&mut m, "ssl.self_signed", "true"); }
        }

        // SSH
        if let Some(ref ssh) = d.ssh {
            push(&mut m, "ssh.raw", &ssh.raw);
            if let Some(ref v) = ssh.key_type     { push(&mut m, "ssh.key_type", v); }
            if let Some(ref v) = ssh.fingerprint  { push(&mut m, "ssh.fingerprint", v); }
            if let Some(ref v) = ssh.product      { push(&mut m, "ssh.product", v); }
            if let Some(ref v) = ssh.version      { push(&mut m, "ssh.version", v); }
        }

        // FTP
        if let Some(ref ftp) = d.ftp {
            if let Some(ref v) = ftp.system { push(&mut m, "ftp.system", v); }
            if let Some(ref v) = ftp.anonymous_listing { push(&mut m, "ftp.anonymous_listing", v); }
            if let Some(ref f) = ftp.features {
                for feat in f { push(&mut m, "ftp.features", feat); }
            }
            if let Some(ref c) = ftp.commands {
                for cmd in c { push(&mut m, "ftp.commands", cmd); }
            }
        }

        // SMTP
        if let Some(ref smtp) = d.smtp {
            if let Some(v) = smtp.starttls { push(&mut m, "smtp.starttls", &v.to_string()); }
            if let Some(ref ehlo) = smtp.ehlo {
                for ext in ehlo { push(&mut m, "smtp.ehlo", ext); }
            }
        }

        // MQTT
        if let Some(ref mqtt) = d.mqtt {
            if let Some(ref v) = mqtt.version { push(&mut m, "mqtt.version", v); }
            if let Some(v) = mqtt.return_code { push(&mut m, "mqtt.return_code", &v.to_string()); }
            for sub in &mqtt.subscriptions { push(&mut m, "mqtt.subscriptions", sub); }
        }

        Evidence(m)
    }
}

fn push(m: &mut BTreeMap<String, Vec<String>>, key: &str, val: &str) {
    m.entry(key.to_string()).or_default().push(val.to_string());
}
