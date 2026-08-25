use anyhow::Result;
use reqwest::Client;
use std::collections::BTreeMap;

use crate::models::HttpData;

pub async fn probe_http(
    ip: &str,
    port: u16,
    tls: bool,
    user_agent: &str,
) -> Result<HttpData> {
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{}://{}:{}/", scheme, ip, port);

    let client = Client::builder()
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::limited(3))
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    let response = client.get(&url).send().await?;
    let status = response.status().as_u16();

    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in response.headers() {
        headers
            .entry(key.to_string())
            .or_default()
            .push(value.to_str().unwrap_or("").to_string());
    }

    let body_bytes = response.bytes().await?;
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();

    let title = extract_title(&body_text);
    let clean_body = strip_html_tags(&body_text);

    Ok(HttpData {
        status,
        title,
        body: Some(clean_body),
        headers,
        favicon_hash: None,
    })
}

fn extract_title(html: &str) -> Option<String> {
    let start = html.find("<title>").map(|i| i + 7)?;
    let end = html[start..].find("</title>")?;
    let title = html[start..start + end].trim().to_string();
    if title.is_empty() {
        None
    } else {
        Some(title)
    }
}

fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_script = false;

    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
            }
            '>' => {
                in_tag = false;
                in_script = false;
            }
            _ if !in_tag && !in_script => {
                result.push(c);
            }
            _ => {}
        }
    }

    result
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_title() {
        assert_eq!(
            extract_title("<html><head><title>Test Page</title></head></html>"),
            Some("Test Page".to_string())
        );
        assert_eq!(extract_title("<html></html>"), None);
    }

    #[test]
    fn test_strip_html_tags() {
        assert_eq!(
            strip_html_tags("<html><body>Hello <b>World</b></body></html>"),
            "Hello World"
        );
    }
}
