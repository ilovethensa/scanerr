use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData};

use crate::engine::ProtocolProbe;
use crate::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct ImapProbe;

impl ProtocolProbe for ImapProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Imap
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("* OK") || text.starts_with("* PREAUTH")
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

    // Reconnect for CAPABILITY command
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
    let _ = net::read_reply(&mut stream, REPLY_TIMEOUT).await;

    // Parse IMAP greeting: "* OK [CAPABILITY IMAP4rev1 ...] ServerName"
    let mut capabilities = Vec::new();
    let mut product = None;

    if let Some(rest) = banner_text.strip_prefix("* OK") {
        if let Some(start) = rest.find('[') {
            if let Some(end) = rest[start..].find(']') {
                let cap_str = &rest[start + 1..start + end];
                for cap in cap_str.split_whitespace() {
                    let cap = cap.trim_matches(';');
                    if !cap.is_empty() {
                        capabilities.push(cap.to_string());
                    }
                }
            }
        }
        if let Some(end) = rest.find(']') {
            let after = rest[end + 1..].trim();
            if !after.is_empty() {
                product = Some(after.to_string());
            }
        }
    }

    // Send CAPABILITY to get full list
    net::send(&mut stream, b"a001 CAPABILITY\r\n").await;
    let cap_buf = net::read_until(&mut stream, REPLY_TIMEOUT, |t| {
        t.contains("a001 OK") || t.contains("a001 BAD")
    })
    .await;

    if !cap_buf.is_empty() {
        let cap_text = String::from_utf8_lossy(&cap_buf).to_string();
        for line in cap_text.lines() {
            if let Some(rest) = line.strip_prefix("* CAPABILITY ") {
                capabilities.clear();
                for cap in rest.split_whitespace() {
                    let cap = cap.trim_matches(';');
                    if !cap.is_empty() {
                        capabilities.push(cap.to_string());
                    }
                }
            }
        }
    }

    net::send(&mut stream, b"a002 NOOP\r\n").await;
    let _ = net::read_reply(&mut stream, REPLY_TIMEOUT).await;

    net::send(&mut stream, b"a003 LOGOUT\r\n").await;

    let banner = if capabilities.is_empty() {
        banner_text.trim().to_string()
    } else {
        format!(
            "{} Capabilities: {}",
            banner_text.trim(),
            capabilities.join(", ")
        )
    };

    Ok(ServiceData {
        banner: Some(banner),
        product,
        ..Default::default()
    })
}
