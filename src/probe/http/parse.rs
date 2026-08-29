use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

pub fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title>")?;
    let tag_start = start + 7;
    let end = lower[tag_start..].find("</title>")?;
    let title = html[tag_start..tag_start + end].trim().to_string();
    if title.is_empty() { None } else { Some(title) }
}

pub fn hash_bytes(data: &[u8]) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let bytes: [u8; 8] = result[..8].try_into().unwrap_or([0; 8]);
    i64::from_be_bytes(bytes)
}

pub fn hash_str(s: &str) -> i64 {
    hash_bytes(s.as_bytes())
}

pub fn header_str(headers: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<String> {
    headers.get(key).and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    })
}

pub fn headers_from_response(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, serde_json::Value> {
    let mut raw: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in headers {
        raw.entry(key.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("").to_string());
    }
    raw.into_iter()
        .map(|(k, v)| {
            let val = if v.len() == 1 {
                serde_json::Value::String(v.into_iter().next().unwrap())
            } else {
                serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
            };
            (k, val)
        })
        .collect()
}
