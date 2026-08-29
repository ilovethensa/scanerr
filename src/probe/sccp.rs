use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, SccpData, ServiceData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

const MSG_REGISTER_REQ: u32 = 0x0001;
const MSG_REGISTER_ACK: u32 = 0x0081;
const MSG_KEEPALIVE_ACK: u32 = 0x0100;
const MSG_VERSION_MESSAGE: u32 = 0x0098;
const MSG_DISPLAY_TEXT: u32 = 0x0099;

pub struct SccpProbe;

impl ProtocolProbe for SccpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Sccp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port).await
    }
}

fn register_req() -> Vec<u8> {
    let mut pkt = vec![0u8; 128];
    pkt[0..4].copy_from_slice(&128u32.to_le_bytes()); // data length
    pkt[8..12].copy_from_slice(&MSG_REGISTER_REQ.to_le_bytes());
    let name = b"scanerr";
    pkt[12..12 + name.len()].copy_from_slice(name);
    pkt[52] = 19; // protocol version
    pkt
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub async fn probe(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

    let req = register_req();
    net::send(&mut stream, &req).await;

    let resp = net::read_reply(&mut stream, REPLY_TIMEOUT).await;
    let buf = resp.as_bytes();

    drop(stream);

    if buf.len() < 12 {
        anyhow::bail!("SCCP response too short ({} bytes)", buf.len());
    }

    let msg_id = le32(buf, 8);

    let msg_name = match msg_id {
        MSG_REGISTER_ACK => "RegisterAck",
        MSG_KEEPALIVE_ACK => "KeepAliveAck",
        MSG_VERSION_MESSAGE => "VersionMessage",
        MSG_DISPLAY_TEXT => "DisplayText",
        _ => {
            anyhow::bail!("Not SCCP: unexpected message ID 0x{:04X}", msg_id);
        }
    };

    let mut data = ServiceData {
        tags: vec!["voip".into()],
        ..Default::default()
    };

    if msg_id == MSG_REGISTER_ACK && buf.len() >= 16 {
        let status = le32(buf, 12);
        if buf.len() >= 18 {
            let keepalive = u16::from_le_bytes([buf[16], buf[17]]);
            data.sccp = Some(SccpData {
                device_name: None,
                device_type: None,
                firmware: None,
                protocol_version: None,
                keepalive_interval: Some(keepalive),
            });
            data.banner = Some(format!(
                "SCCP RegisterAck status={} keepalive={}s",
                status, keepalive
            ));
        } else {
            data.banner = Some(format!("SCCP RegisterAck status={}", status));
        }
    } else if msg_id == MSG_VERSION_MESSAGE && buf.len() >= 16 {
        let version_raw = &buf[12..buf.len().min(buf.len())];
        let version = String::from_utf8_lossy(version_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        data.sccp = Some(SccpData {
            device_name: None,
            device_type: None,
            firmware: if version.is_empty() {
                None
            } else {
                Some(version.clone())
            },
            protocol_version: None,
            keepalive_interval: None,
        });
        data.banner = Some(format!("SCCP VersionMessage: {}", version));
    } else if msg_id == MSG_DISPLAY_TEXT && buf.len() >= 16 {
        let text_raw = &buf[12..buf.len().min(buf.len())];
        let text = String::from_utf8_lossy(text_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        data.banner = Some(format!("SCCP DisplayText: {}", text));
    } else {
        data.banner = Some(format!("SCCP {} (0x{:04X})", msg_name, msg_id));
    }

    if msg_id == MSG_REGISTER_ACK {
        if let Some(extra) = extra_msg(ip, port).await {
            enrich(&mut data, &extra);
        }
    }

    Ok(data)
}

async fn extra_msg(ip: &str, port: u16) -> Option<Vec<u8>> {
    let mut stream = net::connect(ip, port, Duration::from_secs(2)).await.ok()?;

    let req = register_req();
    net::send(&mut stream, &req).await;

    let resp = net::read_reply(&mut stream, REPLY_TIMEOUT).await;
    let buf = resp.into_bytes();

    drop(stream);

    if buf.len() >= 12 {
        Some(buf)
    } else {
        None
    }
}

fn enrich(data: &mut ServiceData, extra: &[u8]) {
    if extra.len() < 12 {
        return;
    }

    let msg_id = le32(extra, 8);
    if msg_id != MSG_REGISTER_ACK || extra.len() < 56 {
        return;
    }

    // Device name at offset 28 (16 bytes)
    if extra.len() >= 44 {
        let name_raw = &extra[28..44];
        let name = String::from_utf8_lossy(name_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if !name.is_empty() {
            data.product = Some(name.clone());
            if let Some(ref mut sccp) = data.sccp {
                sccp.device_name = Some(name);
            }
        }
    }

    // Device type at offset 52
    if extra.len() >= 56 {
        let device_type = le32(extra, 52);
        if device_type != 0 {
            if let Some(ref mut sccp) = data.sccp {
                sccp.device_type = Some(device_type);
            }
        }
    }

    // Protocol version at offset 64
    if extra.len() >= 65 {
        let proto_ver = extra[64];
        if proto_ver != 0 {
            if let Some(ref mut sccp) = data.sccp {
                sccp.protocol_version = Some(proto_ver);
            }
            data.version = Some(format!("SCCP v{}", proto_ver));
        }
    }

    // Firmware load name at offset 110 (32 bytes)
    if extra.len() >= 142 {
        let fw_raw = &extra[110..142];
        let fw = String::from_utf8_lossy(fw_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if !fw.is_empty() {
            if let Some(ref mut sccp) = data.sccp {
                sccp.firmware = Some(fw);
            }
        }
    }
}
