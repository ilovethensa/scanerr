use scanerr::probe::http;
use scanerr::probe::raw;

#[tokio::test]
async fn test_probe_http_plain() {
    // Spin up a mock HTTP server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;

        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><head><title>Test Page</title></head><body>Hello World</body></html>";
        stream.write_all(response).await.ok();
    });

    let data = http::probe_http(
        "http",
        &addr.ip().to_string(),
        addr.port(),
        "test-agent/1.0",
    )
    .await
    .unwrap();

    let http = data.http.as_ref().unwrap();
    assert_eq!(http.status, 200);
    assert_eq!(http.title.as_deref(), Some("Test Page"));
    assert!(http.body.as_deref().unwrap().contains("Hello World"));
    assert_eq!(
        http.headers.get("server").unwrap().as_str().unwrap(),
        "nginx/1.18.0"
    );
}

#[tokio::test]
async fn test_probe_raw_banner_ftp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream
            .write_all(b"220 Welcome to FTP server\r\n")
            .await
            .ok();
    });

    let data = raw::read_raw_banner(
        &addr.ip().to_string(),
        addr.port(),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();

    assert_eq!(data.kind, "ftp");
    assert!(data.banner.as_deref().unwrap().contains("220"));
}

#[tokio::test]
async fn test_probe_raw_banner_unknown() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"RANDOM DATA 12345\r\n").await.ok();
    });

    let data = raw::read_raw_banner(
        &addr.ip().to_string(),
        addr.port(),
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();

    assert_eq!(data.kind, "unknown");
    assert!(data.banner.is_some());
}

#[tokio::test]
async fn test_probe_raw_timeout() {
    // Server that never sends data
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        // Just hold the connection open, don't send anything
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let data = raw::read_raw_banner(
        &addr.ip().to_string(),
        addr.port(),
        std::time::Duration::from_millis(100),
    )
    .await
    .unwrap();

    // Should return unknown with empty raw since we timed out
    assert_eq!(data.kind, "unknown");
}
