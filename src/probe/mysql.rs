use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct MysqlProbe;

impl ProtocolProbe for MysqlProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Mysql
    }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        if bytes.len() > 5 && bytes[4] == 0x0a {
            let rest = String::from_utf8_lossy(&bytes[5..]);
            rest.contains('\0') && (rest.contains("MySQL") || rest.contains("MariaDB"))
        } else {
            false
        }
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port, banner).await
    }
}

pub async fn probe(ip: &str, port: u16, banner: &[u8]) -> Result<ServiceData> {
    let greeting = if !banner.is_empty() {
        banner.to_vec()
    } else {
        let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;
        let handshake = [
            0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00,
        ];

        let first = net::read_reply(&mut stream, REPLY_TIMEOUT).await;
        if first.is_empty() {
            net::send(&mut stream, &handshake).await;
            let second = net::read_reply(&mut stream, REPLY_TIMEOUT).await;
            second.into_bytes()
        } else {
            first.into_bytes()
        }
    };

    let greeting_text = String::from_utf8_lossy(&greeting).to_string();

    let mut version: Option<String> = None;
    let mut server_type: Option<String> = None;

    if greeting.len() > 5 && greeting[4] == 0x0a {
        if let Some(end) = greeting[5..].iter().position(|&b| b == 0) {
            let ver = String::from_utf8_lossy(&greeting[5..5 + end]).to_string();
            version = Some(ver.clone());
            let lower = ver.to_lowercase();
            if lower.contains("mariadb") {
                server_type = Some("MariaDB".into());
            } else if lower.contains("mysql") {
                server_type = Some("MySQL".into());
            }
        }
    } else if greeting.len() > 5 && greeting[4] == 0x09 {
        if let Some(end) = greeting[5..].iter().position(|&b| b == 0) {
            let ver = String::from_utf8_lossy(&greeting[5..5 + end]).to_string();
            version = Some(ver);
            server_type = Some("MySQL".into());
        }
    }

    Ok(ServiceData {
        banner: Some(greeting_text.trim().to_string()),
        version,
        product: server_type,
        ..Default::default()
    })
}
