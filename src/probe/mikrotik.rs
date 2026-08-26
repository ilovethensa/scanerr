use anyhow::Result;

use crate::models::{MikrotikData, Protocol, ServiceData};

use super::engine::ProtocolProbe;

pub struct MikrotikProbe;

impl ProtocolProbe for MikrotikProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Mikrotik
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        bytes == b"\x01\x00\x00\x00"
    }

    async fn probe(&self, _ip: &str, _port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let mut data = ServiceData::default();
        data.kind = "mikrotik".into();
        data.product = Some("MikroTik".into());
        data.tags = vec!["mikrotik".into(), "routeros".into(), "btest".into()];
        data.banner = Some("MikroTik bandwidth-test server".into());

        // The4-byte hello is sufficient for identification — no further
        // interaction needed (matching nmap's passive detection approach).
        // Sending a bandwidth-test command would start a throughput test
        // or require authentication, neither of which is useful here.
        if banner.len() >= 4 && banner[..4] == [0x01, 0x00, 0x00, 0x00] {
            data.mikrotik = Some(MikrotikData { auth_mode: None });
        }

        Ok(data)
    }
}
