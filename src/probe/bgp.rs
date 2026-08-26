use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::models::{Protocol, ServiceData};

use super::engine::ProtocolProbe;

pub struct BgpProbe;

impl ProtocolProbe for BgpProbe {
    fn protocol(&self) -> Protocol { Protocol::Bgp }
    fn requires_probe_without_banner(&self) -> bool { true }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        // BGP messages start with 0xFF (all ones) for 16 bytes, then length, then type
        bytes.len() >= 19 && bytes[..16] == [0xFF; 16] && bytes[18] == 1 // OPEN
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(format!("{}:{}", ip, port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("BGP connect timeout"))?
        .map_err(|e| anyhow::anyhow!("BGP connect failed: {}", e))?;
        stream.set_nodelay(true)?;

        // Build a minimal BGP OPEN message (type=1)
        // Marker: 16 bytes of 0xFF
        // Length: 29 bytes total
        // Type: 1 (OPEN)
        // Version: 4
        // My AS: 65000 (dummy)
        // Hold time: 180
        // BGP ID: 10.0.0.1
        // Opt param length: 0
        let mut open = Vec::with_capacity(29);
        open.extend_from_slice(&[0xFF; 16]); // marker
        open.extend_from_slice(&[0, 29]);     // length
        open.push(1);                          // type: OPEN
        open.push(4);                          // version: 4
        open.extend_from_slice(&[254, 24]);   // AS: 65000
        open.extend_from_slice(&[0, 180]);    // hold time: 180
        open.extend_from_slice(&[10, 0, 0, 1]); // BGP ID
        open.push(0);                          // opt param length

        stream.write_all(&open).await?;

        // Read response
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))?;

        // Check if response is a BGP OPEN (type=1) or NOTIFICATION (type=3)
        if n >= 19 && buf[..16] == [0xFF; 16] {
            let msg_type = buf[18];
            if msg_type == 1 || msg_type == 3 {
                let mut data = ServiceData::default();
                data.kind = "bgp".into();
                data.product = Some("BGP".into());
                data.tags = vec!["bgp".into(), "routing".into()];
                data.banner = Some(format!("BGP type={}", msg_type));
                return Ok(data);
            }
        }

        anyhow::bail!("not BGP");
    }
}
