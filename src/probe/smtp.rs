use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData, SmtpData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct SmtpProbe;

impl ProtocolProbe for SmtpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Smtp
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        (text.starts_with("220 ") || text.starts_with("220-"))
            && (text.contains("ESMTP") || text.contains("SMTP"))
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port, banner).await
    }
}

pub async fn probe(ip: &str, port: u16, banner: &[u8]) -> Result<ServiceData> {
    let banner_text = if !banner.is_empty() {
        String::from_utf8_lossy(banner).to_string()
    } else {
        let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
        net::read_reply(&mut stream, CONNECT_TIMEOUT).await
    };
    let banner_trimmed = banner_text.trim().to_string();

    let (product, version) = parse_banner(&banner_trimmed);

    // Reconnect for EHLO exchange
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
    let _ = net::read_reply(&mut stream, REPLY_TIMEOUT).await;

    net::send(&mut stream, b"EHLO scanerr.local\r\n").await;
    let ehlo_buf = net::read_until(&mut stream, REPLY_TIMEOUT, |t| {
        t.lines().last().is_some_and(|l| l.starts_with("250 "))
    })
    .await;

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

    net::send(&mut stream, b"QUIT\r\n").await;

    Ok(ServiceData {
        banner: Some(banner_trimmed),
        product,
        version,
        smtp: Some(SmtpData {
            ehlo: (!extensions.is_empty()).then_some(extensions),
            starttls: Some(starttls),
        }),
        ..Default::default()
    })
}

fn parse_banner(banner: &str) -> (Option<String>, Option<String>) {
    let rest = banner.strip_prefix("220 ").unwrap_or(banner);
    let esmtp_pos = match rest.find(" ESMTP ") {
        Some(p) => p,
        None => return (None, None),
    };
    let after = &rest[esmtp_pos + 8..];
    let words: Vec<&str> = after.split_whitespace().collect();
    if words.is_empty() {
        return (None, None);
    }
    for (i, w) in words.iter().enumerate() {
        if *w == "-" && i + 1 < words.len() {
            let product = words[i + 1..].join(" ");
            return (Some(product), None);
        }
    }
    let product = words[0].to_string();
    let ver = words.get(1).map(|s| s.to_string());
    (Some(product), ver)
}
