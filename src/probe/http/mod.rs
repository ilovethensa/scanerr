pub mod parse;
pub mod tech;

use std::collections::BTreeMap;
use anyhow::Result;
use reqwest;

use crate::models::{ServiceData, HttpData};

pub async fn probe_http(
    scheme: &str,
    ip: &str,
    port: u16,
    client: &reqwest::Client,
) -> Result<ServiceData> {
    let base_url = format!("{}://{}:{}", scheme, ip, port);

    let resp = client.get(&base_url).send().await?;

    // Follow redirects manually, up to 3 hops
    let mut final_resp = resp;
    let mut redirect_count = 0;
    while (301..=308).contains(&final_resp.status().as_u16()) && redirect_count < 3 {
        if let Some(loc) = final_resp.headers().get("location").and_then(|h| h.to_str().ok()) {
            let next_url = if loc.starts_with("http") {
                loc.to_string()
            } else {
                // Relative URL — resolve against current
                let base = final_resp.url().clone();
                base.join(loc).map(|u| u.to_string()).unwrap_or_default()
            };
            if next_url.is_empty() { break; }
            match client.get(&next_url).send().await {
                Ok(r) => { final_resp = r; redirect_count += 1; }
                Err(_) => break, // redirect target failed — keep current response
            }
        } else {
            break;
        }
    }

    let status = final_resp.status().as_u16();
    let host = final_resp.headers().get("host").and_then(|h| h.to_str().ok()).map(|s| s.to_string());

    let mut raw_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in final_resp.headers() {
        raw_headers
            .entry(key.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("").to_string());
    }
    let headers: BTreeMap<String, serde_json::Value> = raw_headers
        .into_iter()
        .map(|(k, v)| {
            let val = if v.len() == 1 {
                serde_json::Value::String(v.into_iter().next().unwrap())
            } else {
                serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
            };
            (k, val)
        })
        .collect();

    let body_bytes = final_resp.bytes().await.unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).replace('\0', "");

    // Follow JavaScript redirects (e.g. Huawei's document.location.href)
    let body_text = if let Some(js_url) = extract_js_redirect(&body_text) {
        let urls = if js_url.starts_with("http") {
            vec![js_url]
        } else if js_url.starts_with("//") {
            vec![format!("{}:{}", scheme, js_url)]
        } else if js_url.starts_with('/') {
            let http_url = format!("http://{}:{}", ip, port) + &js_url;
            let https_port = if port == 80 { 443 } else { port };
            let https_url = format!("https://{}:{}", ip, https_port) + &js_url;
            if scheme == "http" { vec![http_url, https_url] } else { vec![https_url] }
        } else {
            let http_url = format!("http://{}:{}/", ip, port) + &js_url;
            let https_port = if port == 80 { 443 } else { port };
            let https_url = format!("https://{}:{}/", ip, https_port) + &js_url;
            if scheme == "http" { vec![http_url, https_url] } else { vec![https_url] }
        };
        let mut redirected_body = body_text;
        for url in &urls {
            if let Ok(Ok(redirect_resp)) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.get(url.as_str()).send(),
            ).await {
                let redirect_status = redirect_resp.status().as_u16();
                if redirect_status == 200 {
                    if let Ok(redirect_body) = redirect_resp.bytes().await {
                        let text = String::from_utf8_lossy(&redirect_body).replace('\0', "");
                        if !text.is_empty() {
                            redirected_body = text;
                            break;
                        }
                    }
                }
            }
        }
        redirected_body
    } else {
        body_text
    };

    // Detect plain HTTP sent to an HTTPS server — signal the caller to retry with HTTPS
    if is_https_rejection(status, &body_text) {
        anyhow::bail!("server requires HTTPS");
    }

    let html_hash = parse::hash_bytes(&body_bytes);
    let headers_hash = parse::hash_str(&headers_to_string(&headers));

    let title = parse::extract_title(&body_text);
    let server = header_str(&headers, "server");

    // Fingerprint tech stack from IP request
    let mut tags = tech::detect(&headers, &body_text);

    // Reverse DNS + hostname-based request
    let rdns = reverse_dns(ip).await;
    if let Some(ref hostname) = rdns {
        if let Ok(hostname_tags) = probe_by_hostname(&client, &base_url, hostname).await {
            for tag in hostname_tags {
                if !tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                    tags.push(tag);
                }
            }
        }
    }

    // Fetch robots.txt (non-blocking, best effort)
    let robots = fetch_path(&client, &base_url, "/robots.txt").await;
    let securitytxt = fetch_path(&client, &base_url, "/.well-known/security.txt").await;

    // Fetch favicon for hash
    let favicon_hash = fetch_favicon_hash(&client, &base_url).await;

    let mut http = HttpData {
        status,
        title,
        body: Some(body_text),
        headers,
        favicon_hash,
        server,
        host,
        rdns,
        html_hash: Some(html_hash),
        headers_hash: Some(headers_hash),
        robots,
        securitytxt,
        tags,
        waf: None,
        redirects: Vec::new(),
    };

    // Detect WAF from headers
    http.waf = detect_waf(&http.headers);

    let mut data = ServiceData::default();
    data.kind = scheme.into();
    data.http = Some(http);

    // Capture TLS cert data for HTTPS
    if scheme == "https" {
        if let Ok((_, ssl_data)) = super::tls::tls_connect(ip, port).await {
            if ssl_data.subject_cn.is_some() || ssl_data.issuer_cn.is_some() {
                data.ssl = Some(ssl_data);
            }
        }
    }

    Ok(data)
}

/// Fetch the same URL but with Host header set to the rDNS hostname.
/// Returns any new tech tags found that weren't in the IP request.
async fn probe_by_hostname(
    client: &reqwest::Client,
    base_url: &str,
    hostname: &str,
) -> Result<Vec<String>> {
    let resp = client
        .get(base_url)
        .header("Host", hostname)
        .send()
        .await?;

    let mut raw_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in resp.headers() {
        raw_headers
            .entry(key.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("").to_string());
    }
    let headers: BTreeMap<String, serde_json::Value> = raw_headers
        .into_iter()
        .map(|(k, v)| {
            let val = if v.len() == 1 {
                serde_json::Value::String(v.into_iter().next().unwrap())
            } else {
                serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
            };
            (k, val)
        })
        .collect();

    let body_bytes = resp.bytes().await.unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).replace('\0', "");

    Ok(tech::detect(&headers, &body_text))
}

async fn reverse_dns(ip: &str) -> Option<String> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let mut addrs = tokio::net::lookup_host(format!("{}:0", addr)).await.ok()?;
    let entry = addrs.next()?;
    let hostname = entry.ip().to_string();
    // lookup_host returns the IP back if no PTR record exists
    if hostname != ip.to_string() {
        Some(hostname)
    } else {
        None
    }
}

async fn fetch_path(client: &reqwest::Client, base: &str, path: &str) -> Option<String> {
    let url = format!("{}{}", base, path);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let ct = resp.headers().get("content-type")?.to_str().ok()?.to_lowercase();
    if ct.contains("text/html") || ct.contains("application/json") || ct.contains("image/") {
        return None;
    }
    let text = resp.text().await.ok()?;
    if text.is_empty() || text.len() > 65536 { return None; }
    Some(text)
}

async fn fetch_favicon_hash(client: &reqwest::Client, base: &str) -> Option<i64> {
    let url = format!("{}/favicon.ico", base);
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let bytes = resp.bytes().await.ok()?;
    if bytes.is_empty() { return None; }
    Some(parse::hash_bytes(&bytes))
}

fn detect_waf(headers: &BTreeMap<String, serde_json::Value>) -> Option<String> {
    if let Some(server) = header_str(headers, "server") {
        let s = server.to_lowercase();
        if s.contains("cloudflare") { return Some("Cloudflare".into()); }
        if s.contains("akamaighost") || s.contains("akamai") { return Some("Akamai".into()); }
        if s.contains("yunjiasu") { return Some("Baidu Yunjiasu".into()); }
    }
    if headers.contains_key("x-sucuri-id") { return Some("Sucuri".into()); }
    if headers.contains_key("x-cdn") && header_str(headers, "x-cdk") == Some("Incapsula".into()) {
        return Some("Incapsula".into());
    }
    if headers.contains_key("x-protected-by") { return Some("Barracuda".into()); }
    if let Some(vs) = header_str(headers, "via") {
        if vs.contains("Varnish") { return Some("Varnish".into()); }
    }
    None
}

fn headers_to_string(headers: &BTreeMap<String, serde_json::Value>) -> String {
    let mut parts: Vec<String> = headers.iter().map(|(k, v)| {
        match v {
            serde_json::Value::String(s) => format!("{}: {}", k, s),
            serde_json::Value::Array(arr) => {
                let vals: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                format!("{}: {}", k, vals.join(", "))
            }
            _ => format!("{}: {}", k, v),
        }
    }).collect();
    parts.sort();
    parts.join("\r\n")
}

fn header_str<'a>(headers: &'a BTreeMap<String, serde_json::Value>, key: &str) -> Option<String> {
    headers.get(key).and_then(|v| match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => arr.first().and_then(|v| v.as_str()).map(|s| s.to_string()),
        _ => None,
    })
}

fn extract_js_redirect(body: &str) -> Option<String> {
    // Match concatenated: document.location.href = "https://" + window.location.host + "/" + "relogin.asp"
    let concat = regex::Regex::new(r#"document\.location\.href\s*=\s*["'][^"']*["']\s*\+\s*\w+\.location\.\w+\s*\+\s*["'][^"']*["']\s*\+\s*["']([^"']+)["']"#).ok()?;
    if let Some(caps) = concat.captures(body) {
        return Some(caps[1].to_string());
    }
    // Match meta refresh: <meta http-equiv="refresh" content="0; URL=/path">
    let meta = regex::Regex::new(r#"(?i)content\s*=\s*["']\d+\s*;\s*url=([^"']+)["']"#).ok()?;
    if let Some(caps) = meta.captures(body) {
        return Some(caps[1].to_string());
    }
    // Match simple: document.location.href = "relogin.asp"
    let simple = regex::Regex::new(r#"document\.location\.href\s*=\s*["']([^"']+)["']"#).ok()?;
    if let Some(caps) = simple.captures(body) {
        let url = caps[1].to_string();
        if url.contains("relogin") || url.contains("login") || url.starts_with("/doc/") {
            return Some(url);
        }
    }
    None
}

fn is_https_rejection(status: u16, body: &str) -> bool {
    if status == 400 || status == 495 || status == 496 {
        let lower = body.to_lowercase();
        return lower.contains("https")
            || lower.contains("ssl")
            || lower.contains("tls");
    }
    false
}
