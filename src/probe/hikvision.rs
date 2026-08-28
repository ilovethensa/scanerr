use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::models::{Protocol, ServiceData};

use super::engine::ProtocolProbe;

pub struct HikvisionProbe;

impl ProtocolProbe for HikvisionProbe {
    fn protocol(&self) -> Protocol { Protocol::Hikvision }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        // HikVision binary protocol starts with 4 zero bytes
        bytes.len() >= 4 && bytes[..4] == [0x00, 0x00, 0x00, 0x00]
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            TcpStream::connect(format!("{}:{}", ip, port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Hikvision connect timeout"))?
        .map_err(|e| anyhow::anyhow!("Hikvision connect failed: {}", e))?;
        stream.set_nodelay(true)?;

        // Try ISAPI probe — newer Hikvision cameras respond to HTTP
        let probe = b"GET /ISAPI/System/deviceInfo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        stream.write_all(probe).await?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))?;

        let response = String::from_utf8_lossy(&buf[..n]);

        if response.contains("Hikvision") || response.contains("deviceInfo") || response.contains("DS-") {
            let mut data = ServiceData::default();
            data.kind = "http".into();
            data.product = Some("hikvision".into());
            data.tags = vec!["camera".into(), "surveillance".into(), "iot".into()];
            data.banner = Some(response.lines().next().unwrap_or("").to_string());

            if let Some(start) = response.find("model:") {
                let rest = &response[start + 6..];
                if let Some(end) = rest.find('\n') {
                    let model = rest[..end].trim();
                    if !model.is_empty() {
                        data.product = Some(format!("Hikvision {}", model));
                    }
                }
            }

            return Ok(data);
        }

        anyhow::bail!("not Hikvision");
    }
}
