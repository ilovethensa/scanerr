use anyhow::Result;
use crate::models::{Protocol, Pop3Data, ServiceData};
use super::engine::ProtocolProbe;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub struct Pop3Probe;

impl ProtocolProbe for Pop3Probe {
    fn protocol(&self) -> Protocol { Protocol::Pop3 }

    fn detects_banner(&self, bytes: &[u8]) -> bool {
        let text = String::from_utf8_lossy(bytes);
        text.starts_with("+OK")
    }

    async fn probe(&self, ip: &str, port: u16, banner: &[u8], _ua: &str) -> Result<ServiceData> {
        let stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        let banner_text = String::from_utf8_lossy(banner).trim().to_string();

        // Try CAPA command for capabilities
        writer.write_all(b"CAPA\r\n").await?;
        let mut capabilities = Vec::new();

        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(3), lines.next_line()).await {
                Ok(Ok(Some(line))) => {
                    if line == "." {
                        break;
                    } else if !line.starts_with("-ERR") && !line.starts_with("+OK") {
                        capabilities.push(line);
                    }
                }
                _ => break,
            }
        }

        let _ = writer.write_all(b"QUIT\r\n").await;

        let mut data = ServiceData::default();
        data.kind = "pop3".into();
        data.banner = Some(banner_text.clone());
        data.tags = vec!["pop3".into(), "mail".into()];
        data.pop3 = Some(Pop3Data {
            banner: Some(banner_text.clone()),
            server: Some(banner_text),
            capabilities,
        });

        Ok(data)
    }
}
