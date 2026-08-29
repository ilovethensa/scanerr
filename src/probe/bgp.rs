use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct BgpProbe;

impl ProtocolProbe for BgpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Bgp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        bytes.len() >= 19 && bytes[..16] == [0xFF; 16] && (1..=4).contains(&bytes[18])
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

        // Minimal BGP OPEN (type=1): 16 marker + length + type + version + AS + hold + BGP ID + opt params
        let mut open = Vec::with_capacity(29);
        open.extend_from_slice(&[0xFF; 16]);
        open.extend_from_slice(&[0, 29]);
        open.push(1);
        open.push(4);
        open.extend_from_slice(&[254, 24]); // AS 65000
        open.extend_from_slice(&[0, 180]); // hold 180
        open.extend_from_slice(&[10, 0, 0, 1]); // BGP ID
        open.push(0); // opt param len

        net::send(&mut stream, &open).await;

        let resp = net::read_reply(&mut stream, REPLY_TIMEOUT).await;
        let buf = resp.as_bytes();

        if buf.len() >= 19 && buf[..16] == [0xFF; 16] {
            let msg_type = buf[18];
            if msg_type == 1 || msg_type == 3 {
                return Ok(ServiceData {
                    tags: vec!["networking".into()],
                    banner: Some(format!("BGP type={}", msg_type)),
                    ..Default::default()
                });
            }
        }

        anyhow::bail!("not BGP");
    }
}
