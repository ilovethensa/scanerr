use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TelnetProbe;

impl ProtocolProbe for TelnetProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Telnet
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        bytes[0] == 0xFF || text.contains("login:") || text.contains("Password:")
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
        let text = net::read_reply(&mut stream, READ_TIMEOUT)
            .await
            .trim()
            .to_string();

        if text.is_empty() {
            anyhow::bail!("no telnet banner received");
        }

        if text.bytes().any(|b| b == 0) {
            anyhow::bail!("binary response, not telnet");
        }

        if !text.contains("login")
            && !text.contains("Password")
            && !text.contains("Welcome")
            && !text.contains("prompt")
            && !text.contains("Escape")
            && !text.contains("telnet")
        {
            anyhow::bail!(
                "no telnet markers in: {}",
                text.chars().take(40).collect::<String>()
            );
        }

        Ok(ServiceData {
            tags: vec!["remote-access".into()],
            banner: Some(text),
            ..Default::default()
        })
    }
}
