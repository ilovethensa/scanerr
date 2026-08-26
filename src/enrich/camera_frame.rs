use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::Path;
use tokio::process::Command;

/// HTTP snapshot paths for different camera types, ordered by likelihood.
const HTTP_SNAPSHOT_PATHS: &[&str] = &[
    // Axis
    "/axis-cgi/jpg/image.cgi",
    // MOBOTIX
    "/record/current.jpg",
    // Boa/ACTi/Vivotek
    "/cgi-bin/viewer/video.jpg",
    // Hikvision ISAPI (requires auth, will 401)
    "/ISAPI/Streaming/channels/101/picture",
    // Dahua
    "/cgi-bin/snapshot.cgi?channel=1",
    // Generic
    "/snap.jpg",
    "/snapshot.jpg",
    "/image.jpg",
    "/video.jpg",
    "/current.jpg",
    "/live.jpg",
    "/ch1.jpg",
    "/0.jpg",
    "/1.jpg",
];

/// RTSP paths for different camera types.
const RTSP_PATHS: &[&str] = &[
    "/",
    "/1",
    "/live",
    "/stream1",
    "/ch1",
    "/ch0_0.h264",
    "/Streaming/Channels/101",
    "/cam/realmonitor?channel=1&subtype=0",
    "/h264/ch1/main/av_stream",
];

/// Default credentials to try for RTSP.
const RTSP_CREDS: &[&str] = &["", "admin:", "admin:admin", "admin:12345", "admin:123456"];

/// Capture a frame from an HTTP camera via snapshot endpoints.
pub async fn capture_frame(pool: &PgPool, service_id: i64, assets_dir: &str) -> Result<()> {
    let host_info: (String, i32) = sqlx::query_as(
        "SELECT h.ip::text, s.port FROM services s JOIN hosts h ON s.host_id = h.id WHERE s.id = $1",
    )
    .bind(service_id)
    .fetch_one(pool)
    .await?;

    let ip = host_info.0.split('/').next().unwrap_or(&host_info.0);
    let port = host_info.1;

    // Try HTTP snapshot first
    if let Ok(result) = capture_from_http(&format!("http://{}:{}", ip, port)).await {
        let mut hasher = Sha256::new();
        hasher.update(&result.bytes);
        let sha256 = format!("{:x}", hasher.finalize());

        let dest = Path::new(assets_dir).join(format!("{}.jpg", sha256));
        std::fs::write(&dest, &result.bytes)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO service_assets (service_id, kind, sha256, taken_at) VALUES ($1, 'camera_frame', $2, $3)
             ON CONFLICT (service_id, kind) DO UPDATE SET sha256 = $2, taken_at = $3",
        )
        .bind(service_id)
        .bind(&sha256)
        .bind(now)
        .execute(pool)
        .await?;

        return Ok(());
    }

    // Try RTSP on port 554
    if let Ok(result) = capture_from_rtsp(ip, 554).await {
        let mut hasher = Sha256::new();
        hasher.update(&result.bytes);
        let sha256 = format!("{:x}", hasher.finalize());

        let dest = Path::new(assets_dir).join(format!("{}.jpg", sha256));
        std::fs::write(&dest, &result.bytes)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO service_assets (service_id, kind, sha256, taken_at) VALUES ($1, 'camera_frame', $2, $3)
             ON CONFLICT (service_id, kind) DO UPDATE SET sha256 = $2, taken_at = $3",
        )
        .bind(service_id)
        .bind(&sha256)
        .bind(now)
        .execute(pool)
        .await?;

        return Ok(());
    }

    anyhow::bail!("no frame captured from {}:{}", ip, port)
}

/// Standalone camera frame capture for testing.
pub async fn capture_standalone(target: &str) -> Result<FrameResult> {
    let base_url = if target.starts_with("http") || target.starts_with("rtsp") {
        target.to_string()
    } else {
        format!("http://{}", target)
    };

    if base_url.starts_with("rtsp") {
        let result = capture_from_rtsp_url(&base_url).await?;
        let mut hasher = Sha256::new();
        hasher.update(&result.bytes);
        let sha256 = format!("{:x}", hasher.finalize());
        return Ok(FrameResult {
            sha256,
            path: result.path,
            size: result.bytes.len(),
        });
    }

    // Try HTTP first
    if let Ok(result) = capture_from_http(&base_url).await {
        let mut hasher = Sha256::new();
        hasher.update(&result.bytes);
        let sha256 = format!("{:x}", hasher.finalize());
        return Ok(FrameResult {
            sha256,
            path: result.path,
            size: result.bytes.len(),
        });
    }

    // Extract host from URL for RTSP attempt
    let host = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");

    // Try RTSP
    if let Ok(result) = capture_from_rtsp(host, 554).await {
        let mut hasher = Sha256::new();
        hasher.update(&result.bytes);
        let sha256 = format!("{:x}", hasher.finalize());
        return Ok(FrameResult {
            sha256,
            path: result.path,
            size: result.bytes.len(),
        });
    }

    anyhow::bail!("no frame captured from {}", target)
}

async fn capture_from_http(base_url: &str) -> Result<SnapshotResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    for path in HTTP_SNAPSHOT_PATHS {
        let url = format!("{}{}", base_url, path);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if ct.contains("image/jpeg") || ct.contains("image/jpg") || ct.contains("image/png") {
                    let bytes = resp.bytes().await?;
                    if bytes.len() > 500 {
                        return Ok(SnapshotResult {
                            bytes: bytes.to_vec(),
                            path: path.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    anyhow::bail!("no HTTP snapshot captured from {}", base_url)
}

async fn capture_from_rtsp(ip: &str, port: u16) -> Result<SnapshotResult> {
    for cred in RTSP_CREDS {
        for path in RTSP_PATHS {
            let url = if cred.is_empty() {
                format!("rtsp://{}:{}{}", ip, port, path)
            } else {
                format!("rtsp://{}@{}:{}{}", cred, ip, port, path)
            };

            let tmp_path = "/tmp/rtsp_camera_frame.jpg";

            let output = Command::new("ffmpeg")
                .args([
                    "-rtsp_transport", "tcp",
                    "-i", &url,
                    "-frames:v", "1",
                    "-y",
                    tmp_path,
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => {
                    let bytes = std::fs::read(tmp_path)?;
                    if bytes.len() > 500 {
                        let _ = std::fs::remove_file(tmp_path);
                        return Ok(SnapshotResult {
                            bytes,
                            path: path.to_string(),
                        });
                    }
                }
                _ => {
                    let _ = std::fs::remove_file(tmp_path);
                }
            }
        }
    }

    anyhow::bail!("no RTSP frame captured from {}:{}", ip, port)
}

async fn capture_from_rtsp_url(url: &str) -> Result<SnapshotResult> {
    let tmp_path = "/tmp/rtsp_camera_frame.jpg";

    let output = Command::new("ffmpeg")
        .args([
            "-rtsp_transport", "tcp",
            "-i", url,
            "-frames:v", "1",
            "-y",
            tmp_path,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => {
            let bytes = std::fs::read(tmp_path)?;
            if bytes.len() > 500 {
                let _ = std::fs::remove_file(tmp_path);
                return Ok(SnapshotResult {
                    bytes,
                    path: url.to_string(),
                });
            }
        }
        _ => {
            let _ = std::fs::remove_file(tmp_path);
        }
    }

    anyhow::bail!("no RTSP frame captured from {}", url)
}

struct SnapshotResult {
    bytes: Vec<u8>,
    path: String,
}

#[derive(serde::Serialize)]
pub struct FrameResult {
    pub sha256: String,
    pub path: String,
    pub size: usize,
}
