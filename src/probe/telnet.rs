use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::models::{ServiceData, Protocol};

use super::engine::ProtocolProbe;

pub struct TelnetProbe;

impl ProtocolProbe for TelnetProbe {
    fn protocol(&self) -> Protocol { Protocol::Telnet }
    fn requires_probe_without_banner(&self) -> bool { true }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        // Telnet IAC commands or login prompts
        bytes[0] == 0xFF || text.contains("login:") || text.contains("Password:")
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(format!("{}:{}", ip, port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("telnet connect timeout"))?
        .map_err(|e| anyhow::anyhow!("telnet connect failed: {}", e))?;
        stream.set_nodelay(true)?;

        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))?;

        let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();

        // Must have some data to confirm it's telnet
        if text.is_empty() {
            anyhow::bail!("no telnet banner received");
        }

        // Reject binary responses (TIME protocol, etc.)
        if buf[..n].iter().any(|&b| b == 0) {
            anyhow::bail!("binary response, not telnet");
        }

        // Must contain telnet-like text
        if !text.contains("login") && !text.contains("Password") && !text.contains("Welcome")
            && !text.contains("prompt") && !text.contains("Escape") && !text.contains("telnet") {
            anyhow::bail!("no telnet markers in: {}", text.chars().take(40).collect::<String>());
        }

        let mut data = ServiceData::default();
        data.kind = "telnet".into();
        data.banner = Some(text);
        data.tags = vec!["remote-access".into()];

        Ok(data)
    }
}
