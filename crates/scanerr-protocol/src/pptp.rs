use anyhow::Result;
use std::time::Duration;

use crate::models::{Protocol, ServiceData};

use crate::engine::ProtocolProbe;
use crate::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);

const PPTP_MAGIC: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

pub struct PptpProbe;

impl ProtocolProbe for PptpProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Pptp
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port).await
    }
}

fn sccrq() -> Vec<u8> {
    let mut pkt = vec![0u8; 156];
    pkt[0..2].copy_from_slice(&156u16.to_be_bytes());
    pkt[2..4].copy_from_slice(&1u16.to_be_bytes()); // Message Type = Control
    pkt[4..8].copy_from_slice(&PPTP_MAGIC);
    pkt[8..10].copy_from_slice(&1u16.to_be_bytes()); // Control Type = SCCRQ
    pkt[12..16].copy_from_slice(&0x00010003u32.to_be_bytes()); // Protocol Version
    pkt[16..20].copy_from_slice(&0x00000001u32.to_be_bytes()); // Framing: Async
    pkt[20..24].copy_from_slice(&0x00000001u32.to_be_bytes()); // Bearer: Analog
    let host = b"scanerr";
    pkt[32..32 + host.len()].copy_from_slice(host);
    let vendor = b"scanerr";
    pkt[48..48 + vendor.len()].copy_from_slice(vendor);
    pkt
}

pub async fn probe(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

    // Try reading a banner first (unlikely for PPTP, but check)
    let resp = net::read_reply(&mut stream, Duration::from_secs(2)).await;
    if resp.len() >= 12 {
        let buf = resp.as_bytes();
        if buf.len() >= 8 && buf[4..8] == PPTP_MAGIC {
            return parse(buf);
        }
    }

    // Send SCCRQ
    let sccrq = sccrq();
    net::send(&mut stream, &sccrq).await;

    let buf = net::read_until(&mut stream, REPLY_TIMEOUT, |t| t.len() >= 12).await;

    drop(stream);

    if buf.len() < 12 {
        anyhow::bail!("No PPTP response");
    }

    if buf.len() >= 8 && buf[4..8] != PPTP_MAGIC {
        anyhow::bail!("Not PPTP: no magic cookie in response");
    }

    parse(&buf)
}

fn parse(bytes: &[u8]) -> Result<ServiceData> {
    let control_type = u16::from_be_bytes([bytes[8], bytes[9]]);

    let major = bytes[12];
    let minor = bytes[13];
    let version = format!("{}.{}", major, minor);

    let framing = if bytes.len() >= 18 {
        u16::from_be_bytes([bytes[14], bytes[15]])
    } else {
        0
    };

    let hostname_raw = if bytes.len() >= 44 {
        &bytes[28..44]
    } else {
        &[]
    };
    let hostname = String::from_utf8_lossy(hostname_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    let vendor_raw = if bytes.len() >= 156 {
        &bytes[92..156]
    } else {
        &[]
    };
    let vendor = String::from_utf8_lossy(vendor_raw)
        .trim_end_matches('\0')
        .trim()
        .to_string();

    let control_type_name = match control_type {
        1 => "SCCRQ",
        2 => "SCCRP",
        3 => "StopCCRQ",
        4 => "StopCCRP",
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

    let banner = if features.is_empty() {
        format!("PPTP {} Control Message: {}", version, control_type_name)
    } else {
        format!(
            "PPTP {} Control Message: {} Features: {}",
            version,
            control_type_name,
            features.join(", ")
        )
    };

    let product = if !vendor.is_empty() || !hostname.is_empty() {
        Some(format!("{} {}", vendor, hostname).trim().to_string())
    } else {
        None
    };

    Ok(ServiceData {
        banner: Some(banner),
        product,
        version: Some(version),
        ..Default::default()
    })
}
