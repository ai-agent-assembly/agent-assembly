//! Integration tests for the aa-proxy TCP accept loop and CONNECT handling.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use tokio::sync::broadcast;

use aa_proxy::config::ProxyConfig;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

/// Helper: build a `ProxyConfig` bound to an ephemeral port on localhost.
fn test_config(ca_dir: &std::path::Path) -> ProxyConfig {
    ProxyConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 10,
        llm_only: false,
        denied_hosts: Vec::new(),
        skip_upstream_tls_verify: false,
    }
}

/// Start the proxy server on an ephemeral port and return the actual bound address.
///
/// The proxy runs in a background task; the returned `JoinHandle` can be
/// used to verify it didn't panic.
async fn start_proxy(config: ProxyConfig, ca: CaStore) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // We need the actual bound address, so we bind ourselves and pass it.
    let listener = tokio::net::TcpListener::bind(config.bind_addr).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let cfg = ProxyConfig {
        bind_addr: addr,
        ..config
    };

    let (tx, _rx) = broadcast::channel::<PipelineEvent>(16);
    let server = aa_proxy::proxy::ProxyServer::new(cfg, ca, tx);
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (addr, handle)
}

#[tokio::test]
async fn connect_request_returns_200_connection_established() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = test_config(dir.path());
    let (addr, _handle) = start_proxy(config, ca).await;

    // Connect to the proxy and send a CONNECT request.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read the response line.
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await.unwrap();

    assert!(
        response_line.contains("200"),
        "expected 200 response, got: {response_line}"
    );
}

#[tokio::test]
async fn malformed_request_does_not_crash_server() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = test_config(dir.path());
    let (addr, handle) = start_proxy(config, ca).await;

    // Send garbage and close.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GARBAGE\r\n\r\n").await.unwrap();
    drop(stream);

    // Wait a bit and verify the server is still alive.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!handle.is_finished(), "server should still be running");
}

#[tokio::test]
async fn server_accepts_multiple_sequential_connections() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = test_config(dir.path());
    let (addr, _handle) = start_proxy(config, ca).await;

    for _ in 0..3 {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("200"));
    }
}

/// Start a mock HTTP upstream that returns a fixed response, returning its address.
async fn start_mock_upstream(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Read request (we don't care about the content).
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            // Send a minimal HTTP response.
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    addr
}

#[tokio::test]
async fn plain_http_request_is_forwarded_to_upstream() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = test_config(dir.path());
    let (proxy_addr, _handle) = start_proxy(config, ca).await;

    let upstream_addr = start_mock_upstream("hello from upstream").await;

    // Send a plain HTTP request through the proxy targeting our mock upstream.
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request = format!("GET http://{upstream_addr}/ HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();

    // Read the forwarded response.
    let mut response = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut response).await.unwrap();
    assert!(response.contains("200"), "expected 200 from upstream, got: {response}");

    // Read remaining headers + body.
    let mut full = String::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), reader.read_to_string(&mut full)).await;
    assert!(
        full.contains("hello from upstream"),
        "response body should contain upstream content"
    );
}

#[tokio::test]
async fn connect_to_llm_host_triggers_interception_without_crash() {
    // This test verifies that a CONNECT to a known LLM API host
    // (api.openai.com) goes through the detect_api → Interceptor path
    // without panicking or erroring at the proxy level.
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = test_config(dir.path());
    let (addr, handle) = start_proxy(config, ca).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("200"), "expected 200 for LLM host CONNECT, got: {line}");

    // Drop the connection and verify the server didn't crash.
    drop(reader);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !handle.is_finished(),
        "server should still be running after LLM host CONNECT"
    );
}
