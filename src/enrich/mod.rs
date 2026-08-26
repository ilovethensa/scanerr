pub mod camera_frame;
pub mod favicon;
pub mod rtsp_frame;

use anyhow::Result;
use sqlx::PgPool;

pub enum EnricherKind {
    Favicon,
    RtspFrame,
    CameraFrame,
}

impl EnricherKind {
    pub fn applies_to(&self) -> &[&str] {
        match self {
            EnricherKind::Favicon => &["http", "https"],
            EnricherKind::RtspFrame => &["rtsp"],
            EnricherKind::CameraFrame => &["http", "https"],
        }
    }

    pub async fn run(&self, pool: &PgPool, service_id: i64, assets_dir: &str) -> Result<()> {
        match self {
            EnricherKind::Favicon => {
                favicon::fetch_and_store(pool, service_id, assets_dir).await
            }
            EnricherKind::RtspFrame => {
                rtsp_frame::capture_frame(pool, service_id, assets_dir).await
            }
            EnricherKind::CameraFrame => {
                camera_frame::capture_frame(pool, service_id, assets_dir).await
            }
        }
    }
}

/// List available standalone enrichment types.
pub fn list_types() -> &'static [&'static str] {
    &["favicon", "rtsp_frame", "camera_frame"]
}

/// Run a standalone enrichment by type name against a target string.
pub async fn run_standalone(kind: &str, target: &str) -> Result<String> {
    match kind {
        "favicon" => {
            let result = favicon::fetch_standalone(target).await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }
        "rtsp_frame" => {
            let result = rtsp_frame::capture_standalone(target).await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }
        "camera_frame" => {
            let result = camera_frame::capture_standalone(target).await?;
            Ok(serde_json::to_string_pretty(&result)?)
        }
        _ => anyhow::bail!("unknown enrichment type '{}'. available: {:?}", kind, list_types()),
    }
}
