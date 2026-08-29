use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::models::{MqttData, Protocol, ServiceData};

use super::engine::ProtocolProbe;
use super::net;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct MqttProbe;

impl ProtocolProbe for MqttProbe {
    fn protocol(&self) -> Protocol {
        Protocol::Mqtt
    }

    fn requires_probe_without_banner(&self) -> bool {
        true
    }

    async fn probe(&self, ip: &str, port: u16, _banner: &[u8], _ua: &str) -> Result<ServiceData> {
        probe(ip, port).await
    }
}

async fn probe(ip: &str, port: u16) -> Result<ServiceData> {
    let mut stream = net::connect(ip, port, CONNECT_TIMEOUT).await?;

    let connect = connect_pkt("scanerr");
    net::send(&mut stream, &connect).await;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(REPLY_TIMEOUT, stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))?;

    if n < 4 {
        anyhow::bail!("MQTT: no CONNACK ({} bytes)", n);
    }

    if buf[0] != 0x20 {
        anyhow::bail!("MQTT: not CONNACK (first byte 0x{:02x})", buf[0]);
    }

    let return_code = buf[3];
    let version = "MQTT v3.1.1".to_string();

    let mut subscriptions = Vec::new();

    let sub_sys = sub_pkt("sys_probe_1", "$SYS/#");
    let _ = stream.write_all(&sub_sys).await;
    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .ok();

    let sub_all = sub_pkt("sys_probe_2", "#");
    let _ = stream.write_all(&sub_all).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut msg_buf = [0u8; 4096];
    let mut collected = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, stream.read(&mut msg_buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                collected.extend_from_slice(&msg_buf[..n]);
                parse_topics(&collected, &mut subscriptions);
            }
            _ => break,
        }
    }

    let unsub1 = unsub_pkt("sys_probe_1", "$SYS/#");
    let _ = stream.write_all(&unsub1).await;
    let unsub2 = unsub_pkt("sys_probe_2", "#");
    let _ = stream.write_all(&unsub2).await;

    subscriptions.sort();
    subscriptions.dedup();

    Ok(ServiceData {
        mqtt: Some(MqttData {
            version: Some(version),
            return_code: Some(return_code),
            subscriptions,
        }),
        ..Default::default()
    })
}

fn connect_pkt(client_id: &str) -> Vec<u8> {
    let client_bytes = client_id.as_bytes();
    let remaining = 8 + 2 + client_bytes.len();

    let mut packet = Vec::new();
    packet.push(0x10);
    encode_len(&mut packet, remaining);

    packet.push(0x00);
    packet.push(0x04);
    packet.extend_from_slice(b"MQTT");
    packet.push(0x04); // v3.1.1
    packet.push(0x02); // clean session
    packet.push(0x00);
    packet.push(0x3C); // keepalive 60s

    packet.push((client_bytes.len() >> 8) as u8);
    packet.push(client_bytes.len() as u8);
    packet.extend_from_slice(client_bytes);

    packet
}

fn sub_pkt(packet_id: &str, topic: &str) -> Vec<u8> {
    let id_bytes = packet_id.as_bytes();
    let topic_bytes = topic.as_bytes();
    let remaining = 2 + 2 + topic_bytes.len() + 1;

    let mut packet = Vec::new();
    packet.push(0x82);
    encode_len(&mut packet, remaining);

    let pid: u16 = id_bytes
        .iter()
        .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
    packet.push((pid >> 8) as u8);
    packet.push(pid as u8);

    packet.push((topic_bytes.len() >> 8) as u8);
    packet.push(topic_bytes.len() as u8);
    packet.extend_from_slice(topic_bytes);
    packet.push(0x00); // QoS 0

    packet
}

fn unsub_pkt(packet_id: &str, topic: &str) -> Vec<u8> {
    let id_bytes = packet_id.as_bytes();
    let topic_bytes = topic.as_bytes();
    let remaining = 2 + 2 + topic_bytes.len();

    let mut packet = Vec::new();
    packet.push(0xA2);
    encode_len(&mut packet, remaining);

    let pid: u16 = id_bytes
        .iter()
        .fold(0u16, |acc, &b| acc.wrapping_add(b as u16));
    packet.push((pid >> 8) as u8);
    packet.push(pid as u8);

    packet.push((topic_bytes.len() >> 8) as u8);
    packet.push(topic_bytes.len() as u8);
    packet.extend_from_slice(topic_bytes);

    packet
}

fn encode_len(packet: &mut Vec<u8>, mut len: usize) {
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

fn parse_topics(data: &[u8], topics: &mut Vec<String>) {
    let mut pos = 0;
    while pos < data.len() {
        if pos + 2 > data.len() {
            break;
        }

        let first_byte = data[pos];
        let packet_type = (first_byte >> 4) & 0x0F;

        let (remaining_len, new_pos) = match decode_len(data, pos + 1) {
            Some(v) => v,
            None => break,
        };
        pos = new_pos;

        if pos + remaining_len > data.len() {
            break;
        }

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

fn decode_len(data: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut multiplier = 1;
    let mut value = 0usize;
    let mut pos = start;

    loop {
        if pos >= data.len() {
            return None;
        }
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
