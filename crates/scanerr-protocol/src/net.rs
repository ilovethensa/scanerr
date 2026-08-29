use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Connect to `ip:port` with a timeout and enable TCP_NODELAY.
pub async fn connect(ip: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(format!("{ip}:{port}")))
        .await
        .map_err(|_| anyhow!("connect timeout"))?
        .map_err(|e| anyhow!("connect failed: {e}"))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Read one reply, lossily decoded. Empty string on timeout/EOF/error.
pub async fn read_reply(stream: &mut TcpStream, timeout: Duration) -> String {
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).to_string()
}

/// Accumulate reads until `is_done(text_so_far)`, EOF, or timeout.
pub async fn read_until(
    stream: &mut TcpStream,
    timeout: Duration,
    is_done: impl Fn(&str) -> bool,
) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match tokio::time::timeout(timeout, stream.read(&mut tmp)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                acc.extend_from_slice(&tmp[..n]);
                if let Ok(text) = std::str::from_utf8(&acc) {
                    if is_done(text) {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    acc
}

/// Send bytes. Errors are swallowed (use when the probe doesn't care about write failures).
pub async fn send(stream: &mut TcpStream, cmd: &[u8]) {
    let _ = stream.write_all(cmd).await;
}
