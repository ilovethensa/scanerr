use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: DatabaseConfig,
    pub scanner: ScannerConfig,
    pub probe: ProbeConfig,
    pub enrich: EnrichConfig,
    pub storage: StorageConfig,
    pub webui: WebuiConfig,
    pub signatures: SignaturesConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub discovery_ports: Vec<u16>,
    pub discovery_rate: u32,
    pub deep_scan_ports: Vec<u16>,
    pub deep_scan_rate: u32,
    pub max_probe_queue_depth: u32,
    #[serde(default)]
    pub ranges: Vec<String>,
    pub ranges_file: Option<String>,
    #[serde(default = "default_sweep_chunk_size")]
    pub sweep_chunk_size: usize,
}

fn default_sweep_chunk_size() -> usize {
    20
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    pub concurrency: u32,
    pub timeout_secs: u64,
    pub user_agent: String,
    pub geoip_db_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichConfig {
    pub enabled: Vec<String>,
    pub concurrency: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub assets_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebuiConfig {
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignaturesConfig {
    pub dir: String,
    #[serde(default)]
    pub disable: Vec<String>,
}

pub fn load(path: impl AsRef<Path>) -> Result<Config> {
    let text = std::fs::read_to_string(path.as_ref())
        .with_context(|| format!("reading config from {}", path.as_ref().display()))?;
    let mut config: Config = toml::from_str(&text)?;

    // Load ranges from file if ranges_file is specified
    if let Some(ref ranges_file) = config.scanner.ranges_file {
        let base = path.as_ref().parent().unwrap_or(Path::new("."));
        let ranges_path = base.join(ranges_file);
        if let Ok(ranges_text) = std::fs::read_to_string(&ranges_path) {
            config.scanner.ranges = ranges_text
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
        } else {
            eprintln!("WARNING: ranges_file '{}' not found, ranges will be empty", ranges_path.display());
        }
    }

    // Environment overrides
    if let Ok(db_url) = std::env::var("SCANERR_DB") {
        config.database.url = db_url;
    }

    Ok(config)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                url: "postgres://scanerr:scanerr@localhost/scanerr".into(),
            },
            scanner: ScannerConfig {
                discovery_ports: vec![22, 80, 443],
                discovery_rate: 10000,
                deep_scan_ports: vec![
                    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1723, 3306,
                    3389, 5432, 6379, 8080, 8443,
                ],
                deep_scan_rate: 500,
                max_probe_queue_depth: 50000,
                ranges: vec!["10.0.0.0/8".into()],
                ranges_file: None,
                sweep_chunk_size: 20,
            },
            probe: ProbeConfig {
                concurrency: 128,
                timeout_secs: 5,
                user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36".into(),
                geoip_db_path: None,
            },
            enrich: EnrichConfig {
                enabled: vec!["favicon".into()],
                concurrency: 8,
            },
            storage: StorageConfig {
                assets_dir: "./assets".into(),
            },
            webui: WebuiConfig {
                bind: "127.0.0.1:8080".into(),
            },
            signatures: SignaturesConfig {
                dir: "signatures".into(),
                disable: Vec::new(),
            },
        }
    }
}
