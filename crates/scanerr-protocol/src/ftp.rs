use anyhow::Result;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::models::{FtpData, Protocol, ServiceData};

use crate::engine::ProtocolProbe;
use crate::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
const DATA_TIMEOUT: Duration = Duration::from_secs(5);

pub struct FtpProbe;

impl ProtocolProbe for FtpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Ftp
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("220 ") || text.starts_with("220-")
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

    let software = banner_text.strip_prefix("220 ").and_then(|welcome| {
        let start = welcome.find('(')?;
        let end = welcome[start..].find(')')?;
        Some(welcome[start + 1..start + end].to_string())
    });

    // Reconnect for interactive commands — discard the greeting, already captured above.
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
    let _ = net::read_reply(&mut stream, REPLY_TIMEOUT).await;

    net::send(&mut stream, b"SYST\r\n").await;
    let system = net::read_reply(&mut stream, REPLY_TIMEOUT)
        .await
        .strip_prefix("215 ")
        .map(|s| s.trim().to_string());

    net::send(&mut stream, b"FEAT\r\n").await;
    let feat_buf =
        net::read_until(&mut stream, REPLY_TIMEOUT, |t| t.contains("211 End") || t.contains("211-End"))
            .await;
    let features: Vec<String> = String::from_utf8_lossy(&feat_buf)
        .lines()
        .filter(|l| l.starts_with(' '))
        .map(|l| l.trim())
        .filter(|f| !f.is_empty() && !f.starts_with('-'))
        .map(str::to_string)
        .collect();

    net::send(&mut stream, b"HELP\r\n").await;
    let help_buf = net::read_until(&mut stream, REPLY_TIMEOUT, |t| {
        t.contains("214 Direct") || t.contains("214 End")
    })
    .await;
    let commands: Vec<String> = String::from_utf8_lossy(&help_buf)
        .lines()
        .filter(|l| l.starts_with(' '))
        .flat_map(|l| l.split_whitespace())
        .map(|c| c.trim_end_matches('*').to_string())
        .filter(|c| !c.is_empty() && !c.starts_with('=') && !c.starts_with('-'))
        .collect();

    let anon_listing = try_anonymous_listing(&mut stream).await;
    net::send(&mut stream, b"QUIT\r\n").await;

    Ok(ServiceData {
        product: software,
        banner: Some(banner_text.trim().to_string()),
        ftp: Some(FtpData {
            system,
            features: (!features.is_empty()).then_some(features),
            commands: (!commands.is_empty()).then_some(commands),
            anonymous_listing: anon_listing,
        }),
        ..Default::default()
    })
}

async fn try_anonymous_listing(stream: &mut TcpStream) -> Option<String> {
    net::send(stream, b"USER anonymous\r\n").await;
    if !net::read_reply(stream, REPLY_TIMEOUT)
        .await
        .starts_with("331")
    {
        return None;
    }

    net::send(stream, b"PASS anonymous@\r\n").await;
    if !net::read_reply(stream, REPLY_TIMEOUT)
        .await
        .starts_with("230")
    {
        return None;
    }

    net::send(stream, b"PASV\r\n").await;
    let pasv_resp = net::read_reply(stream, REPLY_TIMEOUT).await;
    let addr = parse_pasv(&pasv_resp)?;
    let mut data_stream = TcpStream::connect(&addr).await.ok()?;

    net::send(stream, b"LIST\r\n").await;
    let listing = net::read_until(&mut data_stream, DATA_TIMEOUT, |_| false).await;
    let _ = net::read_reply(stream, REPLY_TIMEOUT).await;

    (!listing.is_empty()).then(|| String::from_utf8_lossy(&listing).to_string())
}

fn parse_pasv(resp: &str) -> Option<String> {
    let start = resp.find('(')?;
    let end = resp[start..].find(')')?;
    let parts: Vec<&str> = resp[start + 1..start + end].split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let ip = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
    let p1: u16 = parts[4].parse().ok()?;
    let p2: u16 = parts[5].parse().ok()?;
    Some(format!("{}:{}", ip, p1 * 256 + p2))
}
