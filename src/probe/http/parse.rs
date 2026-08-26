use sha2::{Sha256, Digest};

pub fn extract_title(html: &str) -> Option<String> {
    // Case-insensitive <title> tag
    let lower = html.to_lowercase();
    let start = lower.find("<title>")?;
    let tag_start = start + 7;
    let end = lower[tag_start..].find("</title>")?;
    let title = html[tag_start..tag_start + end].trim().to_string();
    if title.is_empty() { None } else { Some(title) }
}

pub fn extract_favicon_hash(_html: &str, body: &[u8]) -> Option<i64> {
    // If there's a favicon link in HTML, we'd need to fetch it separately.
    // For now, hash the body as a proxy. Real implementation fetches /favicon.ico.
    if body.is_empty() { return None; }
    let hash = hash_bytes(body);
    Some(hash)
}

pub fn hash_bytes(data: &[u8]) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    // Take first 8 bytes as i64 (like Shodan's hash)
    let bytes: [u8; 8] = result[..8].try_into().unwrap_or([0; 8]);
    i64::from_be_bytes(bytes)
}

pub fn hash_str(s: &str) -> i64 {
    hash_bytes(s.as_bytes())
}

pub fn extract_robots(body: &str) -> Option<String> {
    // Check if the body itself looks like a robots.txt response
    if body.starts_with("User-agent:") || body.starts_with("Sitemap:") || body.starts_with("#") {
        return Some(body.to_string());
    }
    None
}
