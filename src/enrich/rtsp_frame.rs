use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::Path;
use tokio::process::Command;

const RTSP_PATHS: &[&str] = &["/1", "/live", "/stream1", "/ch1", "/ch0_0.h264"];

pub async fn capture_frame(pool: &PgPool, service_id: i64, assets_dir: &str) -> Result<()> {
    let host_info: (String, i32) = sqlx::query_as(
        "SELECT h.ip::text, s.port FROM services s JOIN hosts h ON s.host_id = h.id WHERE s.id = $1",
    )
    .bind(service_id)
    .fetch_one(pool)
    .await?;

    let ip = host_info.0.split('/').next().unwrap_or(&host_info.0);
    let port = host_info.1;

    for path in RTSP_PATHS {
        let url = format!("rtsp://{}:{}{}", ip, port, path);
        let tmp_path = format!("{}/rtsp_frame_{}.jpg", assets_dir, service_id);

        let output = Command::new("ffmpeg")
            .args([
                "-rtsp_transport", "tcp",
                "-i", &url,
                "-frames:v", "1",
                "-y",
                &tmp_path,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                let bytes = std::fs::read(&tmp_path)?;
                if bytes.len() < 100 {
                    let _ = std::fs::remove_file(&tmp_path);
                    continue;
                }

                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let sha256 = format!("{:x}", hasher.finalize());

                let dest = Path::new(assets_dir).join(format!("{}.jpg", sha256));
                std::fs::rename(&tmp_path, &dest)?;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                sqlx::query(
                    "INSERT INTO service_assets (service_id, kind, sha256, taken_at) VALUES ($1, 'rtsp_frame', $2, $3)
                     ON CONFLICT (service_id, kind) DO UPDATE SET sha256 = $2, taken_at = $3",
                )
                .bind(service_id)
                .bind(&sha256)
                .bind(now)
                .execute(pool)
                .await?;

                sqlx::query(
                    "UPDATE services SET data = jsonb_set(data, '{rtsp,frame_sha256}', $1::jsonb) WHERE id = $2",
                )
                .bind(serde_json::json!(sha256))
                .bind(service_id)
                .execute(pool)
                .await?;

                return Ok(());
            }
            _ => {
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
    }

    Ok(())
}

pub async fn capture_standalone(target: &str) -> Result<FrameResult> {
    let mut last_err = String::new();

    for path in RTSP_PATHS {
        let url = format!("rtsp://{}{}", target, path);
        let tmp = "/tmp/rtsp_standalone_frame.jpg";

        let output = Command::new("ffmpeg")
            .args([
                "-rtsp_transport", "tcp",
                "-i", &url,
                "-frames:v", "1",
                "-y",
                tmp,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await?;

        if output.status.success() {
            let bytes = std::fs::read(tmp)?;
            if bytes.len() < 100 {
                let _ = std::fs::remove_file(tmp);
                last_err = format!("frame too small ({} bytes)", bytes.len());
                continue;
            }

            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha256 = format!("{:x}", hasher.finalize());

            let _ = std::fs::remove_file(tmp);

            return Ok(FrameResult {
                sha256,
                path: path.to_string(),
                size: bytes.len(),
            });
        } else {
            last_err = String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("unknown error")
                .to_string();
        }

        let _ = std::fs::remove_file(tmp);
    }

    anyhow::bail!("no frame captured from {}: {}", target, last_err);
}

#[derive(serde::Serialize)]
pub struct FrameResult {
    pub sha256: String,
    pub path: String,
    pub size: usize,
}
