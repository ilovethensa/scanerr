use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::ServiceData;

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct PptpProbe;

impl ProtocolProbe for PptpProbe {
    fn protocol(&self) -> Protocol { Protocol::Pptp }
    fn requires_probe_without_banner(&self) -> bool { true }
    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_pptp(ip, port).await
    }
}

/// Magic cookie that identifies PPTP control messages: 0x1A2B3C4D
const PPTP_MAGIC: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

/// Build a PPTP Start-Control-Connection-Request (SCCRQ).
///
/// Layout (big-endian):
///   0-1:  Length (156 bytes)
///   2-3:  Message Type (1 = Control)
///   4-7:  Magic Cookie (0x1A2B3C4D)
///   8-9:  Control Type (1 = SCCRQ)
///  10-11: Reserved (0)
///  12-15: Protocol Version (0x00010003)
///  16-19: Framing Capabilities (0x00000001 = Async framing)
///  20-23: Bearer Capabilities (0x00000001 = Analog)
///  24-27: Maximum Channels (0)
///  28-31: Firmware Revision (0)
///  32-47: Host Name (16 bytes, ASCII)
///  48-111: Vendor (64 bytes, ASCII)
/// 112-155: Reserved (44 bytes of zeros)
fn build_sccrq() -> Vec<u8> {
    let mut pkt = vec![0u8; 156];
    // Length
    pkt[0..2].copy_from_slice(&156u16.to_be_bytes());
    // Message Type = 1 (Control)
    pkt[2..4].copy_from_slice(&1u16.to_be_bytes());
    // Magic Cookie
    pkt[4..8].copy_from_slice(&PPTP_MAGIC);
    // Control Type = 1 (SCCRQ)
    pkt[8..10].copy_from_slice(&1u16.to_be_bytes());
    // Protocol Version 1.0 (0x00010003)
    pkt[12..16].copy_from_slice(&0x00010003u32.to_be_bytes());
    // Framing Capabilities: Async framing
    pkt[16..20].copy_from_slice(&0x00000001u32.to_be_bytes());
    // Bearer Capabilities: Analog
    pkt[20..24].copy_from_slice(&0x00000001u32.to_be_bytes());
    // Host Name: "scanerr"
    let host = b"scanerr";
    pkt[32..32 + host.len()].copy_from_slice(host);
    // Vendor: "scanerr"
    let vendor = b"scanerr";
    pkt[48..48 + vendor.len()].copy_from_slice(vendor);
    pkt
}

/// Probe a PPTP server on port 1723.
///
/// 1. Connect and try to read a banner (some servers send data first).
/// 2. Send SCCRQ and read the response.
/// 3. Check for PPTP magic cookie to confirm.
pub async fn probe_pptp(ip: &str, port: u16) -> Result<ServiceData> {
    let connect_timeout = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(format!("{}:{}", ip, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("PPTP connect timeout"))?
    .map_err(|e| anyhow::anyhow!("PPTP connect failed: {}", e))?;

    let mut stream = connect_timeout;
    stream.set_nodelay(true)?;

    // Try reading a banner first (unlikely for PPTP, but check)
    let mut buf = [0u8; 4096];
    let has_banner = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))
    .unwrap_or(0);

    if has_banner >= 12 {
        let magic = &buf[4..8];
        if magic == PPTP_MAGIC {
            return parse_pptp_response(&buf[..has_banner]);
        }
    }

    // Send SCCRQ
    let sccrq = build_sccrq();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.write_all(&sccrq),
    )
    .await
    .map_err(|_| anyhow::anyhow!("PPTP write timeout"))??;

    // Read response
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    drop(stream);

    if n < 12 {
        anyhow::bail!("No PPTP response");
    }

    let magic = &buf[4..8];
    if magic != PPTP_MAGIC {
        anyhow::bail!("Not PPTP: no magic cookie in response");
    }

    parse_pptp_response(&buf[..n])
}

fn parse_pptp_response(bytes: &[u8]) -> Result<ServiceData> {
    let control_type = u16::from_be_bytes([bytes[8], bytes[9]]);

    // Protocol Version: 2 bytes major at offset 12, 1 byte minor at offset 14
    let major = bytes[12];
    let minor = bytes[13];
    let version = format!("{}.{}", major, minor);

    // Framing capabilities at offset 14-17
    let framing = if bytes.len() >= 18 {
        u16::from_be_bytes([bytes[14], bytes[15]])
    } else {
        0
    };

    // Host Name at offset 28-43 (16 bytes, null-padded)
    let hostname_raw = if bytes.len() >= 44 { &bytes[28..44] } else { &[] };
    let hostname = String::from_utf8_lossy(hostname_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    // Vendor Name at offset 92-155 (64 bytes, null-padded)
    let vendor_raw = if bytes.len() >= 156 { &bytes[92..156] } else { &[] };
    let vendor = String::from_utf8_lossy(vendor_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    let control_type_name = match control_type {
        1 => "SCCRQ (Start-Control-Connection-Request)",
        2 => "SCCRP (Start-Control-Connection-Reply)",
        3 => "StopCCRQ (Stop-Control-Connection-Request)",
        4 => "StopCCRP (Stop-Control-Connection-Reply)",
        5 => "Echo-Request",
        6 => "Echo-Reply",
        _ => "Unknown",
    };

    let mut features: Vec<String> = Vec::new();
    if framing & 0x1 != 0 {
        features.push("Async Framing".into());
    }
    if framing & 0x2 != 0 {
        features.push("Sync Framing".into());
    }
    features.push(format!("Control: {}", control_type_name));

    let mut data = ServiceData::default();
    data.kind = "pptp".into();
    let banner = if features.is_empty() {
        format!("PPTP {} Control Message: {}", version, control_type_name)
    } else {
        format!("PPTP {} Control Message: {} Features: {}",
            version, control_type_name, features.join(", "))
    };
    data.banner = Some(banner);
    data.product = if !vendor.is_empty() || !hostname.is_empty() {
        Some(format!("{} {}", vendor, hostname).trim().to_string())
    } else {
        None
    };
    data.version = Some(version);

    Ok(data)
}
