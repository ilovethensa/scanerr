use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::ServiceData;

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct MysqlProbe;

impl ProtocolProbe for MysqlProbe {
    fn protocol(&self) -> Protocol { Protocol::Mysql }
    fn detects_banner(&self, bytes: &[u8]) -> bool {
        if bytes.len() > 5 && bytes[4] == 0x0a {
            let rest = String::from_utf8_lossy(&bytes[5..]);
            rest.contains('\0') && (rest.contains("MySQL") || rest.contains("MariaDB"))
        } else {
            false
        }
    }
    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_mysql(ip, port).await
    }
}

pub async fn probe_mysql(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    // MySQL servers should send a greeting immediately, but some wait.
    // Send a minimal handshake response to trigger the server.
    // HandshakeResponse41 packet: protocol 4.1, max packet 0, charset utf8, username "root"
    let handshake = [
        0x00, 0x00, 0x01, 0x85, // packet number + flags
        0xa6, 0x03, 0x00, 0x00, // max packet size
        0x00,                     // charset utf8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // reserved
        // username null-terminated
        0x72, 0x6f, 0x6f, 0x74, 0x00, // "root\0"
    ];

    // First try reading without sending (server might send greeting)
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    let greeting = if n > 0 {
        buf[..n].to_vec()
    } else {
        // No greeting — send handshake response to trigger server response
        stream.write_all(&handshake).await.ok();
        let n2 = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))?;
        buf[..n2].to_vec()
    };

    let greeting_text = String::from_utf8_lossy(&greeting).to_string();

    // Parse MySQL greeting: starts with packet length (3 bytes) + sequence (1 byte) + protocol version (1 byte = 0x0a)
    let mut version: Option<String> = None;
    let mut server_type: Option<String> = None;

    if greeting.len() > 5 && greeting[4] == 0x0a {
        // Protocol version 10 (modern MySQL)
        // Server version is a null-terminated string starting at byte 5
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
        // Protocol version 9 (old MySQL)
        if let Some(end) = greeting[5..].iter().position(|&b| b == 0) {
            let ver = String::from_utf8_lossy(&greeting[5..5 + end]).to_string();
            version = Some(ver);
            server_type = Some("MySQL".into());
        }
    }

    // Try to read error packet if handshake failed
    if version.is_none() && !greeting.is_empty() {
        // Might be an error packet — read more
        let more = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        if more > 0 {
            let full = [&greeting[..], &buf[..more]].concat();
            let full_text = String::from_utf8_lossy(&full).to_string();
            let mut data = ServiceData::default();
            data.kind = "mysql".into();
            data.banner = Some(full_text.trim().to_string());
            if let Some(v) = version {
                data.version = Some(v);
            }
            if let Some(s) = server_type {
                data.product = Some(s.clone());
            }
            stream.write_all(b"QUIT\r\n").await.ok();
            return Ok(data);
        }
    }

    stream.write_all(b"QUIT\r\n").await.ok();

    let mut data = ServiceData::default();
    data.kind = "mysql".into();
    data.banner = Some(greeting_text.trim().to_string());
    if let Some(v) = version {
        data.version = Some(v);
    }
    if let Some(s) = server_type {
        data.product = Some(s.clone());
    }

    Ok(data)
}
