use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::{Protocol, SccpData, ServiceData};

use super::engine::ProtocolProbe;

pub struct SccpProbe;

impl ProtocolProbe for SccpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Sccp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_sccp(ip, port).await
    }
}

// ─── SCCP message IDs ────────────────────────────────────────────────────────

/// Station → CallManager
const MSG_REGISTER_REQ: u32 = 0x0001;

/// CallManager → Station (valid SCCP responses)
const MSG_REGISTER_ACK: u32 = 0x0081;
const MSG_KEEPALIVE_ACK: u32 = 0x0100;
const MSG_VERSION_MESSAGE: u32 = 0x0098;
const MSG_DISPLAY_TEXT: u32 = 0x0099;

// ─── Probe implementation ────────────────────────────────────────────────────

/// Build an SCCP RegisterReq message.
///
/// Layout (little-endian):
///   0-3:  Data length (128 bytes)
///   4-7:  Header version (0)
///   8-11: Message ID (1 = RegisterReq)
///  12-27: Device name (16 bytes, null-padded ASCII)
///  28-31: Reserved (0)
///  32-35: Instance (0)
///  36-39: Station IPv4 address (0)
///  40-43: Device type (0)
///  44-47: Max concurrent RTP streams (0)
///  48-51: Active RTP streams (0)
///    52:  Protocol version (19)
///    53:  Unknown (0)
///  54-55: Phone features (0)
///  56-59: Max concurrent conferences (0)
///  60-63: Active conferences (0)
///  64-69: MAC address (6 bytes, zeros)
///  70-73: IPv4 address scope (0)
///  74-77: Max number of lines (0)
///  78-93: Station IPv6 address (16 bytes, zeros)
///  94-97: IPv6 address scope (0)
///  98-129: Firmware load name (32 bytes, null-padded)
fn build_register_req() -> Vec<u8> {
    let mut pkt = vec![0u8; 128];
    // Data length
    pkt[0..4].copy_from_slice(&128u32.to_le_bytes());
    // Message ID = 1 (RegisterReq)
    pkt[8..12].copy_from_slice(&MSG_REGISTER_REQ.to_le_bytes());
    // Device name: "scanerr" (16 bytes, null-padded)
    let name = b"scanerr";
    pkt[12..12 + name.len()].copy_from_slice(name);
    // Protocol version = 19
    pkt[52] = 19;
    pkt
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Probe an SCCP server (typically on port 2000).
///
/// Sends a RegisterReq and checks the response for a valid SCCP header.
pub async fn probe_sccp(ip: &str, port: u16) -> Result<ServiceData> {
    let connect_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SCCP connect timeout"))?
    .map_err(|e| anyhow::anyhow!("SCCP connect failed: {}", e))?;

    let mut stream = connect_timeout;
    stream.set_nodelay(true)?;

    // Send RegisterReq
    let req = build_register_req();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.write_all(&req),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SCCP write timeout"))??;

    // Read response
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    drop(stream);

    if n < 12 {
        anyhow::bail!("SCCP response too short ({} bytes)", n);
    }

    let msg_id = read_u32_le(&buf, 8);

    // Validate it looks like SCCP — message ID must be a known response type
    let msg_name = match msg_id {
        MSG_REGISTER_ACK => "RegisterAck",
        MSG_KEEPALIVE_ACK => "KeepAliveAck",
        MSG_VERSION_MESSAGE => "VersionMessage",
        MSG_DISPLAY_TEXT => "DisplayText",
        _ => {
            anyhow::bail!(
                "Not SCCP: unexpected message ID 0x{:04X}",
                msg_id
            );
        }
    };

    let mut data = ServiceData::default();
    data.kind = "sccp".into();
    data.tags = vec!["voip".into()];

    // ── Parse RegisterAck (msg_id 0x0081) ──────────────────────────────────
    if msg_id == MSG_REGISTER_ACK && n >= 16 {
        // RegisterAck payload (12 bytes after header):
        //   12-15: Status (u32 LE) — 0 = Ok
        //   16-17: Keepalive interval (u16 LE, seconds)
        let status = read_u32_le(&buf, 12);
        if n >= 18 {
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
    }
    // ── Parse VersionMessage (msg_id 0x0098) ──────────────────────────────
    else if msg_id == MSG_VERSION_MESSAGE && n >= 16 {
        // VersionMessage payload: version as null-terminated ASCII at offset 12
        let version_raw = &buf[12..n.min(buf.len())];
        let version = String::from_utf8_lossy(version_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        data.sccp = Some(SccpData {
            device_name: None,
            device_type: None,
            firmware: if version.is_empty() { None } else { Some(version.clone()) },
            protocol_version: None,
            keepalive_interval: None,
        });
        data.banner = Some(format!("SCCP VersionMessage: {}", version));
    }
    // ── Parse DisplayText (msg_id 0x0099) ─────────────────────────────────
    else if msg_id == MSG_DISPLAY_TEXT && n >= 16 {
        let text_raw = &buf[12..n.min(buf.len())];
        let text = String::from_utf8_lossy(text_raw)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        data.banner = Some(format!("SCCP DisplayText: {}", text));
    }
    // ── KeepAliveAck or other — just confirm SCCP ─────────────────────────
    else {
        data.banner = Some(format!("SCCP {} (0x{:04X})", msg_name, msg_id));
    }

    // If we got a RegisterAck, try to extract device info from a second connection
    if msg_id == MSG_REGISTER_ACK {
        if let Some(extra) = read_extra_message(ip, port).await {
            enrich_from_extra(&mut data, &extra);
        }
    }

    Ok(data)
}

/// Read one more message from the server to extract device info.
async fn read_extra_message(ip: &str, port: u16) -> Option<Vec<u8>> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    .ok()?
    .ok()?;

    stream.set_nodelay(true).ok()?;

    // Send another RegisterReq to provoke device info
    let req = build_register_req();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.write_all(&req),
    )
    .await
    .ok()?
    .ok()?;

    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;

    drop(stream);

    if n >= 12 { Some(buf[..n].to_vec()) } else { None }
}

/// Try to extract device name, type, and firmware from a RegisterAck response.
///
/// RegisterAck layout (little-endian):
///   0-3:   Data length (u32)
///   4-7:   Header version (u32)
///   8-11:  Message ID (0x0081)
///  12-15:  Status (u32) — 0 = Ok
///  16-19:  Keepalive interval (u16 LE at 16, padding at 18)
///  20-27:  Unknown / reserved
///  28-43:  Device name (16 bytes, null-terminated ASCII)
///  44-47:  Max protocol version (u32 LE)
///  48-51:  Unknown (u32 LE)
///  52-55:  Device type (u32 LE)
///  56-59:  Max concurrent RTP streams (u32 LE)
///  60-63:  Active RTP streams (u32 LE)
///    64:   Protocol version (u8)
///    65:   Unknown (u8)
///  66-67:  Phone features (u16 LE)
///  68-71:  Max concurrent conferences (u32 LE)
///  72-75:  Active conferences (u32 LE)
///  76-81:  MAC address (6 bytes)
///  82-85:  IPv4 address scope (u32 LE)
///  86-89:  Max number of lines (u32 LE)
///  90-105: Station IPv6 address (16 bytes)
/// 106-109: IPv6 address scope (u32 LE)
/// 110-141: Firmware load name (32 bytes, null-terminated ASCII)
fn enrich_from_extra(data: &mut ServiceData, extra: &[u8]) {
    if extra.len() < 12 {
        return;
    }

    let msg_id = read_u32_le(extra, 8);
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

    // Device type at offset 52 (u32 LE)
    if extra.len() >= 56 {
        let device_type = read_u32_le(extra, 52);
        if device_type != 0 {
            if let Some(ref mut sccp) = data.sccp {
                sccp.device_type = Some(device_type);
            }
        }
    }

    // Protocol version at offset 64 (u8)
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
