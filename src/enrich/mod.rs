pub mod favicon;

use anyhow::Result;
use sqlx::PgPool;

pub enum EnricherKind {
    Favicon,
}

impl EnricherKind {
    pub fn applies_to(&self) -> &[&str] {
        match self {
            EnricherKind::Favicon => &["http", "https"],
        }
    }

    pub async fn run(&self, pool: &PgPool, service_id: i64, assets_dir: &str) -> Result<()> {
        match self {
            EnricherKind::Favicon => {
                favicon::fetch_and_store(pool, service_id, assets_dir).await
            }
        }
    }
}

/// List available standalone enrichment types.
pub fn list_types() -> &'static [&'static str] {
    &["favicon"]
}

/// Run a standalone enrichment by type name against a target string.
/// Format: enrich::run_standalone("favicon", "http://192.168.1.1:80/favicon.ico")
pub async fn run_standalone(kind: &str, target: &str) -> Result<String> {
    match kind {
        "favicon" => {
            let result = favicon::fetch_standalone(target).await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }
        _ => anyhow::bail!("unknown enrichment type '{}'. available: {:?}", kind, list_types()),
    }
}
