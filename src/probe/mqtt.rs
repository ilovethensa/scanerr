use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::models::{MqttData, ServiceData};

use super::engine::ProtocolProbe;
use crate::models::Protocol;

pub struct MqttProbe;

impl ProtocolProbe for MqttProbe {
    fn protocol(&self) -> Protocol { Protocol::Mqtt }
    fn requires_probe_without_banner(&self) -> bool { true }
    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe_mqtt(ip, port).await
    }
}

pub async fn probe_mqtt(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;
    stream.set_nodelay(true)?;

    // Send CONNECT packet (MQTT v3.1.1, clean session, no auth)
    let connect = build_connect("scanerr");
    eprintln!("[mqtt] sending CONNECT ({} bytes): {:02x?}", connect.len(), &connect);
    stream.write_all(&connect).await?;
    stream.flush().await?;

    // Read CONNACK
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    .unwrap_or(Ok(0))?;

    eprintln!("[mqtt] read {} bytes from {}:{} buf={:02x?}", n, ip, port, &buf[..n.min(16)]);

    if n < 4 {
        anyhow::bail!("MQTT: no CONNACK ({} bytes)", n);
    }

    // Validate it's a CONNACK (0x20)
    if buf[0] != 0x20 {
        anyhow::bail!("MQTT: not CONNACK (first byte 0x{:02x})", buf[0]);
    }

    let return_code = buf[3];
    let version = "MQTT v3.1.1".to_string();

    // Try subscribing to wildcard topics to discover what's available
    let mut subscriptions = Vec::new();

    // Subscribe to $SYS/# for broker info
    let sub_sys = build_subscribe("sys_probe_1", "$SYS/#");
    let _ = stream.write_all(&sub_sys).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_until_timeout(&mut stream, &mut buf),
    ).await.ok();

    // Subscribe to # for all topics
    let sub_all = build_subscribe("sys_probe_2", "#");
    let _ = stream.write_all(&sub_all).await;

    // Collect messages for a short window
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut msg_buf = [0u8; 4096];
    let mut collected = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() { break; }

        match tokio::time::timeout(remaining, stream.read(&mut msg_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&msg_buf[..n]);
                // Parse PUBLISH packets to extract topic names
                parse_topics_from_packets(&collected, &mut subscriptions);
            }
            _ => break,
        }
    }

    // Unsubscribe cleanly
    let unsub1 = build_unsubscribe("sys_probe_1", "$SYS/#");
    let _ = stream.write_all(&unsub1).await;
    let unsub2 = build_unsubscribe("sys_probe_2", "#");
    let _ = stream.write_all(&unsub2).await;

    subscriptions.sort();
    subscriptions.dedup();

    let mut data = ServiceData::default();
    data.kind = "mqtt".into();
    data.mqtt = Some(MqttData {
        version: Some(version),
        return_code: Some(return_code),
        subscriptions,
    });

    Ok(data)
}

fn build_connect(client_id: &str) -> Vec<u8> {
    let client_bytes = client_id.as_bytes();
    // Variable header: protocol name "MQTT" (4 bytes) + level 4 (1) + flags (1) + keepalive (2) = 8 bytes
    // Payload: client ID length (2) + client ID
    let remaining = 8 + 2 + client_bytes.len();

    let mut packet = Vec::new();
    packet.push(0x10); // CONNECT fixed header
    encode_remaining_length(&mut packet, remaining);

    // Variable header
    // Protocol name
    packet.push(0x00); packet.push(0x04);
    packet.extend_from_slice(b"MQTT");
    // Protocol level (4 = v3.1.1)
    packet.push(0x04);
    // Connect flags: clean session
    packet.push(0x02);
    // Keep alive
    packet.push(0x00); packet.push(0x3C); // 60 seconds

    // Payload: client ID
    packet.push((client_bytes.len() >> 8) as u8);
    packet.push(client_bytes.len() as u8);
    packet.extend_from_slice(client_bytes);

    packet
}

fn build_subscribe(packet_id: &str, topic: &str) -> Vec<u8> {
    let id_bytes = packet_id.as_bytes();
    let topic_bytes = topic.as_bytes();
    // Variable header: packet id (2) + topic filter length (2) + topic + QoS (1)
    let remaining = 2 + 2 + topic_bytes.len() + 1;

    let mut packet = Vec::new();
    packet.push(0x82); // SUBSCRIBE fixed header (0x80 | 0x02)
    encode_remaining_length(&mut packet, remaining);

    // Packet ID (use first 2 bytes of id hash or just 0x0001)
    let pid: u16 = id_bytes.iter().fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
    packet.push((pid >> 8) as u8);
    packet.push(pid as u8);

    // Topic filter
    packet.push((topic_bytes.len() >> 8) as u8);
    packet.push(topic_bytes.len() as u8);
    packet.extend_from_slice(topic_bytes);

    // QoS 0
    packet.push(0x00);

    packet
}

fn build_unsubscribe(packet_id: &str, topic: &str) -> Vec<u8> {
    let id_bytes = packet_id.as_bytes();
    let topic_bytes = topic.as_bytes();
    let remaining = 2 + 2 + topic_bytes.len();

    let mut packet = Vec::new();
    packet.push(0xA2); // UNSUBSCRIBE
    encode_remaining_length(&mut packet, remaining);

    let pid: u16 = id_bytes.iter().fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
    packet.push((pid >> 8) as u8);
    packet.push(pid as u8);

    packet.push((topic_bytes.len() >> 8) as u8);
    packet.push(topic_bytes.len() as u8);
    packet.extend_from_slice(topic_bytes);

    packet
}

fn encode_remaining_length(packet: &mut Vec<u8>, mut len: usize) {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        packet.push(byte);
        if len == 0 {
            break;
        }
    }
}

fn parse_topics_from_packets(data: &[u8], topics: &mut Vec<String>) {
    let mut pos = 0;
    while pos < data.len() {
        if pos + 2 > data.len() { break; }

        let first_byte = data[pos];
        let packet_type = (first_byte >> 4) & 0x0F;

        // Decode remaining length
        let (remaining_len, new_pos) = match decode_remaining_length(data, pos + 1) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;

        if pos + remaining_len > data.len() { break; }

        if packet_type == 3 {
            // PUBLISH — extract topic
            if remaining_len >= 2 {
                let topic_len = ((data[pos] as usize) << 8) | data[pos + 1] as usize;
                if pos + 2 + topic_len <= data.len() {
                    if let Ok(topic) = std::str::from_utf8(&data[pos + 2..pos + 2 + topic_len]) {
                        topics.push(topic.to_string());
                    }
                }
            }
        }

        pos += remaining_len;
    }
}

fn decode_remaining_length(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut multiplier = 1;
    let mut value = 0usize;
    let mut pos = start;

    loop {
        if pos >= data.len() { return None; }
        let byte = data[pos];
        value += (byte & 0x7F) as usize * multiplier;
        pos += 1;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return None;
        }
    }
}

async fn read_until_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    let _ = stream.read(buf).await?;
    Ok(())
}
