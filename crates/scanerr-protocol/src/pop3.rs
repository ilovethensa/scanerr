use anyhow::Result;
use std::time::Duration;

use crate::models::{Pop3Data, Protocol, ServiceData};

use crate::engine::ProtocolProbe;
use crate::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Pop3Probe;

impl ProtocolProbe for Pop3Probe {
    fn protocol(&self) -> Protocol {
        Protocol::Pop3
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("+OK")
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

        let banner_text = String::from_utf8_lossy(banner).trim().to_string();

        // Send CAPA
        net::send(&mut stream, b"CAPA\r\n").await;
        let cap_buf = net::read_until(&mut stream, REPLY_TIMEOUT, |t| {
            t.lines().last().is_some_and(|l| l == ".")
        })
        .await;

        let capabilities: Vec<String> = String::from_utf8_lossy(&cap_buf)
            .lines()
            .filter(|l| !l.starts_with("-ERR") && !l.starts_with("+OK") && *l != ".")
            .map(str::to_string)
            .collect();

        net::send(&mut stream, b"QUIT\r\n").await;

        Ok(ServiceData {
            tags: vec!["mail".into()],
            pop3: Some(Pop3Data {
                banner: Some(banner_text.clone()),
                server: Some(banner_text),
                capabilities,
            }),
            ..Default::default()
        })
    }
}
