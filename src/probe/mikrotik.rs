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

    async fn probe(&self, _ip: &str, _port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        Ok(ServiceData {
            product: Some("mikrotik".into()),
            tags: vec!["networking".into()],
            banner: Some("MikroTik bandwidth-test server".into()),
            mikrotik: Some(MikrotikData { auth_mode: None }),
            ..Default::default()
        })
    }
}
