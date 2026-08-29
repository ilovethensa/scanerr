use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, RtspData, ServiceData};

use crate::engine::ProtocolProbe;
use crate::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct RtspProbe;

impl ProtocolProbe for RtspProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Rtsp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port).await
    }
}

async fn probe(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

    let request = format!("OPTIONS rtsp://{}:{} RTSP/1.0\r\nCSeq: 1\r\n\r\n", ip, port);
    net::send(&mut stream, request.as_bytes()).await;

    let resp = net::read_reply(&mut stream, REPLY_TIMEOUT).await;

    if resp.is_empty() {
        anyhow::bail!("RTSP: empty response");
    }

    if !resp.starts_with("RTSP/") {
        anyhow::bail!(
            "Not RTSP: {}",
            resp.chars().take(40).collect::<String>()
        );
    }

    let status_line = resp.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut server = None;
    let mut public = None;
    for line in resp.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some(val) = line.strip_prefix("Server:") {
            server = Some(val.trim().to_string());
        }
        if let Some(val) = line.strip_prefix("Public:") {
            public = Some(val.trim().to_string());
        }
    }

    Ok(ServiceData {
        tags: vec!["camera".into()],
        product: server.clone(),
        banner: Some(format!("RTSP/1.0 {}", status_code)),
        rtsp: Some(RtspData {
            server,
            public,
            frame_sha256: None,
        }),
        ..Default::default()
    })
}
