use anyhow::{Context, Result};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: String,
    pub port: u16,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_id() -> u64 {
    // Use PID + atomic counter for globally unique IDs across containers
    let pid = std::process::id() as u64;
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    pid.wrapping_mul(1_000_000).wrapping_add(seq)
}

fn masscan_scan(targets: &[String], ports: &[u16], rate: u32) -> Result<Vec<ScanResult>> {
    let port_str = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let id = unique_id();
    let targets_file = format!("/tmp/masscan_targets_{}.txt", id);
    let output_file = format!("/tmp/masscan_out_{}.json", id);

    let targets_str = targets.join("\n");
    std::fs::write(&targets_file, &targets_str)
        .context("failed to write masscan targets file")?;

    let output = Command::new("masscan")
        .arg("-iL")
        .arg(&targets_file)
        .arg("-p")
        .arg(&port_str)
        .arg("--rate")
        .arg(rate.to_string())
        .arg("--retries")
        .arg("2")
        .arg("--open")
        .arg("--output-format")
        .arg("json")
        .arg("--output-filename")
        .arg(&output_file)
        .output()
        .context("failed to execute masscan")?;

    let _ = std::fs::remove_file(&targets_file);

    let json = std::fs::read_to_string(&output_file).unwrap_or_default();
    let _ = std::fs::remove_file(&output_file);

    if json.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("masscan produced no output: {}", stderr);
    }

    parse_masscan_json(&json)
}

pub fn run_stage1(cidr: &str, ports: &[u16], rate: u32) -> Result<Vec<ScanResult>> {
    masscan_scan(&[cidr.to_string()], ports, rate)
}

pub fn run_stage1_batch(ranges: &[String], ports: &[u16], rate: u32) -> Result<Vec<ScanResult>> {
    masscan_scan(ranges, ports, rate)
}

pub fn run_stage2(ip: &str, ports: &[u16], rate: u32) -> Result<Vec<ScanResult>> {
    let port_str = ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let id = unique_id();
    let targets_file = format!("/tmp/masscan_targets_{}.txt", id);
    let output_file = format!("/tmp/masscan_out_{}.json", id);

    std::fs::write(&targets_file, ip)
        .context("failed to write masscan targets file")?;

    let output = Command::new("masscan")
        .arg("-iL")
        .arg(&targets_file)
        .arg("-p")
        .arg(&port_str)
        .arg("--rate")
        .arg(rate.to_string())
        .arg("--output-format")
        .arg("json")
        .arg("--retries")
        .arg("2")
        .arg("--open")
        .arg("--output-filename")
        .arg(&output_file)
        .output()
        .context("failed to execute masscan")?;

    let json = std::fs::read_to_string(&output_file).unwrap_or_default();
    let _ = std::fs::remove_file(&output_file);
    let _ = std::fs::remove_file(&targets_file);

    if json.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("masscan produced no output: {}", stderr);
    }

    parse_masscan_json(&json)
}

pub fn parse_masscan_json(json: &str) -> Result<Vec<ScanResult>> {
    let v: serde_json::Value = serde_json::from_str(json)
        .context("failed to parse masscan JSON output")?;

    let mut results = Vec::new();

    if let Some(items) = v.as_array() {
        for item in items {
            if let Some(ip) = item["ip"].as_str() {
                if let Some(ports) = item["ports"].as_array() {
                    for port_obj in ports {
                        if let Some(port) = port_obj["port"].as_u64() {
                            results.push(ScanResult {
                                ip: ip.to_string(),
                                port: port as u16,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_masscan_json() {
        let json = r#"[
  {"ip": "192.168.1.1", "timestamp": "1234", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
  {"ip": "192.168.1.2", "timestamp": "1234", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]}
]"#;
        let results = parse_masscan_json(json).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ip, "192.168.1.1");
        assert_eq!(results[0].port, 80);
        assert_eq!(results[1].ip, "192.168.1.2");
        assert_eq!(results[1].port, 443);
    }

    #[test]
    fn test_parse_multi_port() {
        let json = r#"[
  {"ip": "10.0.0.1", "timestamp": "1234", "ports": [
    {"port": 22, "proto": "tcp", "status": "open"},
    {"port": 80, "proto": "tcp", "status": "open"}
  ]}
]"#;
        let results = parse_masscan_json(json).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].port, 22);
        assert_eq!(results[1].port, 80);
    }

    #[test]
    fn test_parse_empty_json() {
        let json = r#"[]"#;
        let results = parse_masscan_json(json).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_malformed_json() {
        let json = r#"not json"#;
        let result = parse_masscan_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_banner_json() {
        let json = r#"[
  {"ip": "192.168.1.111", "timestamp": "1787656017", "ports": [{"port": 80, "proto": "tcp", "service": {"name": "http.server", "banner": "Caddy"}}]}
]"#;
        let results = parse_masscan_json(json).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ip, "192.168.1.111");
        assert_eq!(results[0].port, 80);
    }
}
