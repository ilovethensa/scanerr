use scanerr::probe::http;

#[tokio::test]
async fn test_probe_http_plain() {
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

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(8))
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .unwrap();

    let data = http::probe(
        "http",
        &addr.ip().to_string(),
        addr.port(),
        &client,
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
