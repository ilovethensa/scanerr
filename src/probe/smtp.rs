use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::ServiceData;

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct SmtpProbe;

impl ProtocolProbe for SmtpProbe {
    fn protocol(&self) -> Protocol { Protocol::Smtp }
    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        (text.starts_with("220 ") || text.starts_with("220-"))
            && (text.contains("ESMTP") || text.contains("SMTP"))
    }
    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_smtp(ip, port, banner).await
    }
}

pub async fn probe_smtp(ip: &str, port: u16, _banner: &[u8]) -> Result<ServiceData> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    // Read banner
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    let banner_text = String::from_utf8_lossy(&buf[..n]).to_string();
    let banner_trimmed = banner_text.trim().to_string();

    // Parse product/version from banner: "220 mail.example.com ESMTP Postfix"
    let (product, version) = parse_smtp_banner(&banner_trimmed);

    // EHLO
    stream.write_all(b"EHLO scanerr.local\r\n").await.ok();
    let mut ehlo_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut tmp),
        ).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                ehlo_buf.extend_from_slice(&tmp[..n]);
                if let Ok(text) = std::str::from_utf8(&ehlo_buf) {
                    // Multi-line responses: lines starting with "250-" are continuation,
                    // "250 " (space) is the final line
                    if let Some(last_line) = text.lines().last() {
                        if last_line.starts_with("250 ") {
                            break;
                        }
                    }
                }
            }
            _ => break,
        }
    }

    let mut extensions = Vec::new();
    let mut starttls = false;
    if !ehlo_buf.is_empty() {
        let ehlo_text = String::from_utf8_lossy(&ehlo_buf).to_string();
        for line in ehlo_text.lines() {
            if line.starts_with("250-") || line.starts_with("250 ") {
                let ext = line[4..].trim().to_string();
                if !ext.is_empty() {
                    if ext.eq_ignore_ascii_case("STARTTLS") {
                        starttls = true;
                    }
                    extensions.push(ext);
                }
            }
        }
    }

    stream.write_all(b"QUIT\r\n").await.ok();

    let mut data = ServiceData::default();
    data.kind = "smtp".into();
    data.banner = Some(banner_trimmed);
    data.product = product;
    data.version = version;
    data.smtp = Some(crate::models::SmtpData {
        ehlo: if extensions.is_empty() { None } else { Some(extensions) },
        starttls: Some(starttls),
    });

    Ok(data)
}

/// Parse: "220 mail.example.com ESMTP Postfix" → (Some("Postfix"), None)
/// Parse: "220 mx.google.com ESMTP <id> - gsmtp" → (Some("gsmtp"), None)
fn parse_smtp_banner(banner: &str) -> (Option<String>, Option<String>) {
    let rest = banner.strip_prefix("220 ").unwrap_or(banner);
    if let Some(esmtp_pos) = rest.find(" ESMTP ") {
        let after = &rest[esmtp_pos + 8..];
        let words: Vec<&str> = after.split_whitespace().collect();
        if words.is_empty() {
            return (None, None);
        }
        // Skip session IDs (contain dots and hex chars), look for the real product
        // Format: "ESMTP <session-id> - gsmtp" or "ESMTP Postfix" or "ESMTP Exim 4.95"
        // The product after " - " is the real one (e.g. gsmtp, Microsoft ESMTP)
        for (i, w) in words.iter().enumerate() {
            if *w == "-" && i + 1 < words.len() {
                // Everything after " - " is the product
                let product_words: Vec<&str> = words[i + 1..].to_vec();
                let product = product_words.join(" ");
                return (Some(product), None);
            }
        }
        // No " - " found — first word might be the product if it looks like a name
        // Skip obvious session IDs (contain mixed hex/dash like "a640c23a62f3a-c250")
        let first = words[0];
        if first.contains('-') && first.len() > 12 {
            // Looks like a session ID, skip it
            return (None, None);
        }
        let product = first.to_string();
        let ver = words.get(1).map(|s| s.to_string());
        return (Some(product), ver);
    }
    (None, None)
}
