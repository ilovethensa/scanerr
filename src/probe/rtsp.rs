use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::{Protocol, RtspData, ServiceData};

use super::engine::ProtocolProbe;

pub struct RtspProbe;

impl ProtocolProbe for RtspProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Rtsp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_rtsp(ip, port).await
    }
}

/// Probe an RTSP server (typically port 554).
///
/// Sends an OPTIONS request and parses Server/Public headers from the response.
async fn probe_rtsp(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("RTSP connect timeout"))?
    .map_err(|e| anyhow::anyhow!("RTSP connect failed: {}", e))?;

    stream.set_nodelay(true)?;

    // Send OPTIONS request
    let request = format!(
        "OPTIONS rtsp://{}:{} RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        ip, port
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("RTSP write timeout"))??;

    // Read response
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    drop(stream);

    if n == 0 {
        anyhow::bail!("RTSP: empty response");
    }

    let response = String::from_utf8_lossy(&buf[..n]);

    // Must start with RTSP/
    if !response.starts_with("RTSP/") {
        anyhow::bail!("Not RTSP: {}", response.chars().take(40).collect::<String>());
    }

    // Parse status line: RTSP/1.0 200 OK
    let status_line = response.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Parse headers
    let mut server = None;
    let mut public = None;
    for line in response.lines().skip(1) {
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

    let mut data = ServiceData::default();
    data.kind = "rtsp".into();
    data.tags = vec!["rtsp".into()];

    if let Some(ref s) = server {
        data.product = Some(s.clone());
        data.tags.push(s.to_lowercase());
    }

    data.banner = Some(format!("RTSP/1.0 {}", status_code));

    data.rtsp = Some(RtspData { server, public, frame_sha256: None });

    Ok(data)
}
