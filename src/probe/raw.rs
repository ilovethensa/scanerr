use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::models::ServiceData;

pub async fn read_raw_banner(
    ip: &str,
    port: u16,
    timeout: std::time::Duration,
) -> Result<ServiceData> {
    let mut stream = TcpStream::connect(format!("{}:{}", ip, port)).await?;

    let result = tokio::time::timeout(timeout, async {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        buf[..n].to_vec()
    })
    .await;

    let bytes = result.unwrap_or_default();
    let banner = String::from_utf8_lossy(&bytes).to_string();

    let mut data = ServiceData::default();

    if banner.starts_with("SSH-") {
        data.kind = "ssh".into();
        data.raw = Some(banner);
        data.tags.push("ssh".into());
    } else if banner.starts_with("220 ") || banner.contains("FTP") {
        data.kind = "ftp".into();
        data.raw = Some(banner);
        data.tags.push("ftp".into());
    } else {
        data.kind = "unknown".into();
        if !banner.is_empty() {
            data.raw = Some(banner);
        }
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_raw_banner_ssh() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").await.ok();
        });

        let data = read_raw_banner(
            &addr.ip().to_string(),
            addr.port(),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(data.kind, "ssh");
        assert!(data.tags.contains(&"ssh".to_string()));
    }
}
