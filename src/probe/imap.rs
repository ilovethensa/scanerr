use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::ServiceData;

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct ImapProbe;

impl ProtocolProbe for ImapProbe {
    fn protocol(&self) -> Protocol { Protocol::Imap }
    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("* OK") || text.starts_with("* PREAUTH")
    }
    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_imap(ip, port).await
    }
}

pub async fn probe_imap(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    // IMAP servers send a greeting immediately: "* OK [CAPABILITY ...] ..."
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    let banner_text = String::from_utf8_lossy(&buf[..n]).to_string();

    // Parse IMAP greeting: "* OK [CAPABILITY IMAP4rev1 ...] ServerName"
    let mut capabilities = Vec::new();
    let mut product = None;

    if let Some(rest) = banner_text.strip_prefix("* OK") {
        // Extract capabilities from [...]
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
        // Server name is usually after the bracket block
        if let Some(end) = rest.find(']') {
            let after = rest[end + 1..].trim();
            if !after.is_empty() {
                product = Some(after.to_string());
            }
        }
    }

    // Send CAPABILITY command to get full list
    stream.write_all(b"a001 CAPABILITY\r\n").await.ok();
    let mut cap_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut tmp),
        ).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                cap_buf.extend_from_slice(&tmp[..n]);
                let text = String::from_utf8_lossy(&cap_buf);
                if text.contains("a001 OK") || text.contains("a001 BAD") {
                    break;
                }
            }
            _ => break,
        }
    }

    if !cap_buf.is_empty() {
        let cap_text = String::from_utf8_lossy(&cap_buf).to_string();
        // Parse "* CAPABILITY IMAP4rev1 IDLE ..."
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

    // Try NOOP for server identification
    stream.write_all(b"a002 NOOP\r\n").await.ok();
    let mut noop_buf = [0u8; 4096];
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut noop_buf),
    ).await;

    stream.write_all(b"a003 LOGOUT\r\n").await.ok();

    let mut data = ServiceData::default();
    data.kind = "imap".into();
    let banner = if capabilities.is_empty() {
        banner_text.trim().to_string()
    } else {
        format!("{} Capabilities: {}", banner_text.trim(), capabilities.join(", "))
    };
    data.banner = Some(banner);
    data.product = product;

    Ok(data)
}
