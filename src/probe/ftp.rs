use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::ServiceData;

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct FtpProbe;

impl ProtocolProbe for FtpProbe {
    fn protocol(&self) -> Protocol { Protocol::Ftp }
    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("220 ") || text.starts_with("220-")
    }
    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_ftp(ip, port, banner).await
    }
}

pub async fn probe_ftp(ip: &str, port: u16, _banner: &[u8]) -> Result<ServiceData> {
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
    let mut software = None;

    if let Some(welcome) = banner_text.strip_prefix("220 ") {
        if let Some(start) = welcome.find('(') {
            if let Some(end) = welcome[start..].find(')') {
                software = Some(welcome[start+1..start+end].to_string());
            }
        }
    }

    // SYST
    stream.write_all(b"SYST\r\n").await.ok();
    let mut syst_buf = [0u8; 4096];
    let syst_n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut syst_buf),
    )
    .await
    .unwrap_or(Ok(0))
    .unwrap_or(0);

    let system = if syst_n > 0 {
        let syst_text = String::from_utf8_lossy(&syst_buf[..syst_n]).to_string();
        syst_text.strip_prefix("215 ").map(|s| s.trim().to_string())
    } else {
        None
    };

    // FEAT
    stream.write_all(b"FEAT\r\n").await.ok();
    let mut feat_buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut tmp),
        ).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                feat_buf.extend_from_slice(&tmp[..n]);
                if let Ok(text) = std::str::from_utf8(&feat_buf) {
                    if text.contains("211 End") || text.contains("211-End") {
                        break;
                    }
                }
            }
            _ => break,
        }
    }

    let mut features = Vec::new();
    if !feat_buf.is_empty() {
        let feat_text = String::from_utf8_lossy(&feat_buf).to_string();
        for line in feat_text.lines() {
            if line.starts_with(' ') {
                let feat = line.trim();
                if !feat.is_empty() && !feat.starts_with('-') {
                    features.push(feat.to_string());
                }
            }
        }
    }

    // HELP — full command list
    stream.write_all(b"HELP\r\n").await.ok();
    let mut help_buf = Vec::new();
    let mut tmp2 = [0u8; 4096];
    loop {
        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut tmp2),
        ).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                help_buf.extend_from_slice(&tmp2[..n]);
                if let Ok(text) = std::str::from_utf8(&help_buf) {
                    if text.contains("214 Direct") || text.contains("214 End") {
                        break;
                    }
                }
            }
            _ => break,
        }
    }

    let commands = if !help_buf.is_empty() {
        let help_text = String::from_utf8_lossy(&help_buf).to_string();
        let cmds: Vec<String> = help_text.lines()
            .filter(|l| l.starts_with(' '))
            .flat_map(|l| l.split_whitespace())
            .map(|c| c.trim_end_matches('*').to_string())
            .filter(|c| !c.is_empty() && !c.starts_with('=') && !c.starts_with('-'))
            .collect();
        if cmds.is_empty() { None } else { Some(cmds) }
    } else {
        None
    };

    // Try anonymous login
    let mut anon_listing = None;
    stream.write_all(b"USER anonymous\r\n").await.ok();
    let mut user_buf = [0u8; 4096];
    let user_n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut user_buf),
    )
    .await
    .unwrap_or(Ok(0))
    .unwrap_or(0);

    let user_resp = String::from_utf8_lossy(&user_buf[..user_n]).to_string();

    if user_resp.starts_with("331") {
        // Password required, send empty password
        stream.write_all(b"PASS anonymous@\r\n").await.ok();
        let mut pass_buf = [0u8; 4096];
        let pass_n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut pass_buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        let pass_resp = String::from_utf8_lossy(&pass_buf[..pass_n]).to_string();

        if pass_resp.starts_with("230") {
            // Login successful — try to list
            // First try PASV
            stream.write_all(b"PASV\r\n").await.ok();
            let mut pasv_buf = [0u8; 4096];
            let pasv_n = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                stream.read(&mut pasv_buf),
            )
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0);

            let pasv_resp = String::from_utf8_lossy(&pasv_buf[..pasv_n]).to_string();

            if let Some(addr) = parse_pasv(&pasv_resp) {
                // Connect to data port
                if let Ok(mut data_stream) = TcpStream::connect(&addr).await {
                    // LIST
                    stream.write_all(b"LIST\r\n").await.ok();

                    let mut listing = Vec::new();
                    let mut data_tmp = [0u8; 4096];
                    loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            data_stream.read(&mut data_tmp),
                        ).await {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => listing.extend_from_slice(&data_tmp[..n]),
                            _ => break,
                        }
                    }

                    // Read the transfer complete response from control channel
                    let mut resp_buf = [0u8; 4096];
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(3),
                        stream.read(&mut resp_buf),
                    ).await;

                    if !listing.is_empty() {
                        let text = String::from_utf8_lossy(&listing).to_string();
                        anon_listing = Some(text);
                    }
                }
            }
        }
    }

    stream.write_all(b"QUIT\r\n").await.ok();

    let mut data = ServiceData::default();
    data.kind = "ftp".into();
    data.product = software;
    data.banner = Some(banner_text.trim().to_string());
    data.ftp = Some(crate::models::FtpData {
        system,
        features: if features.is_empty() { None } else { Some(features) },
        commands,
        anonymous_listing: anon_listing,
    });

    Ok(data)
}

/// Parse PASV response: "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)"
/// Returns "h1.h2.h3.h4:(p1*256+p2)" string
fn parse_pasv(resp: &str) -> Option<String> {
    let start = resp.find('(')?;
    let end = resp[start..].find(')')?;
    let inner = &resp[start + 1..start + end];
    let parts: Vec<&str> = inner.split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let ip = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
    let p1: u16 = parts[4].parse().ok()?;
    let p2: u16 = parts[5].parse().ok()?;
    let port = p1 * 256 + p2;
    Some(format!("{}:{}", ip, port))
}
