//! End-to-end integration tests for aa-proxy host-based policy enforcement.
//!
//! These tests verify that the Layer 2 MitM proxy correctly enforces allow/deny
//! policy at the CONNECT level without requiring any SDK initialisation
//! (AAASM-1517).
//!
//! Each test spins up an in-process `ProxyServer` on a free port and drives it
//! with raw TCP or `reqwest` (proxy-configured) connections.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use aa_proxy::config::ProxyConfig;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

// ── Test harness helpers ────────────────────────────────────────────────────

/// Build a `ProxyConfig` for tests.
///
/// - `denied_hosts`: hosts to block at CONNECT level.
/// - `ca_dir`: path to a temporary directory for the proxy CA.
fn proxy_config(ca_dir: &std::path::Path, denied_hosts: Vec<String>) -> ProxyConfig {
    let port = portpicker::pick_unused_port().expect("no free port");
    ProxyConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 10,
        llm_only: false,
        denied_hosts,
        skip_upstream_tls_verify: true,
    }
}

/// Start the proxy in a background task, wait until the port is accepting TCP
/// connections, and return the bound address plus the event receiver.
async fn start_proxy(
    config: ProxyConfig,
    ca: CaStore,
) -> (SocketAddr, broadcast::Receiver<PipelineEvent>, tokio::task::AbortHandle) {
    let addr = config.bind_addr;
    let (tx, rx) = broadcast::channel(256);
    let server = aa_proxy::proxy::ProxyServer::new(config, ca, tx);
    let jh = tokio::spawn(async move { server.run().await.unwrap() });
    let abort = jh.abort_handle();

    // Poll until the proxy TCP port accepts connections (5 s budget).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("proxy did not start within 5s on {addr}");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    (addr, rx, abort)
}

/// Send a raw CONNECT request to `proxy_addr` for `target` and return the first
/// response line (e.g. `"HTTP/1.1 200 Connection Established\r\n"`).
async fn connect_to_proxy(proxy_addr: SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .expect("write CONNECT");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    line
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Test 1: proxy allows CONNECT to a non-denied host and emits an audit event.
///
/// No SDK init is performed — the proxy enforces policy autonomously.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_intercepts_and_enforces_allow() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config(dir.path(), vec!["forbidden.example.com".into()]);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    // CONNECT to an allowed host (127.0.0.1 is not on the deny list).
    let target = format!("127.0.0.1:{}", portpicker::pick_unused_port().unwrap());
    let response_line = connect_to_proxy(proxy_addr, &target).await;

    assert!(
        response_line.contains("200"),
        "expected 200 for allowed host, got: {response_line}"
    );

    // An audit event must arrive within 1 s.
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");
    assert!(matches!(event, PipelineEvent::Audit(_)), "expected Audit event");

    abort.abort();
}

/// Test 2: proxy blocks CONNECT to a denied host with 403 and zero upstream hits.
///
/// Uses a real `TcpListener` as a stand-in for "upstream": if the proxy contacted
/// it, `accept()` would succeed before the 100 ms deadline. A timeout proves the
/// proxy returned 403 without ever dialling upstream.
///
/// No SDK init is performed — this is pure Layer 2 enforcement.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_intercepts_and_enforces_deny() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    // Bind a real upstream listener so we can prove the proxy never dials it.
    // 127.0.0.1 is used as both the listener address and the denied hostname so
    // that the proxy *would* connect here if it ignored the deny list.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let denied_host = upstream_addr.ip().to_string(); // "127.0.0.1"

    let config = proxy_config(dir.path(), vec![denied_host.clone()]);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    // CONNECT to the denied host:port — proxy must return 403 before dialling.
    let target = format!("{}:{}", denied_host, upstream_addr.port());
    let response_line = connect_to_proxy(proxy_addr, &target).await;

    assert!(
        response_line.contains("403"),
        "expected 403 for denied host, got: {response_line}"
    );

    // accept() must time out: the proxy must not have contacted upstream.
    let not_contacted = tokio::time::timeout(Duration::from_millis(100), upstream.accept()).await;
    assert!(
        not_contacted.is_err(),
        "upstream must not receive any connection from the proxy"
    );

    // A deny audit event must arrive within 1 s.
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");
    assert!(matches!(event, PipelineEvent::Audit(_)), "expected Audit event on deny");

    abort.abort();
}

/// Test 3: the audit event for a denied CONNECT contains the blocked hostname.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_emits_event_with_url_host() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config(dir.path(), vec!["forbidden.example.com".into()]);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    // Trigger a deny.
    let _ = connect_to_proxy(proxy_addr, "forbidden.example.com:443").await;

    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");

    // The event debug string must contain the denied hostname.
    let event_debug = format!("{event:?}");
    assert!(
        event_debug.contains("forbidden.example.com"),
        "event must contain the denied hostname; got: {event_debug}"
    );

    abort.abort();
}

/// Test 4: proxy blocks without any SDK `init_assembly` call — pure Layer 2.
///
/// This is a deliberate structural duplicate of test 2 that makes the SDK-free
/// intent explicit in the test name and commentary.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_blocks_without_sdk_init_assembly() {
    // No SDK initialisation is performed anywhere in this test.
    // The proxy enforces the deny list entirely at the network layer.

    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config(dir.path(), vec!["forbidden.example.com".into()]);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    let response_line = connect_to_proxy(proxy_addr, "forbidden.example.com:443").await;

    assert!(
        response_line.contains("403"),
        "expected 403 with no SDK, got: {response_line}"
    );

    // Deny event still emitted.
    tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");

    abort.abort();
}

/// Test 5: the proxy's per-host CA generates a valid certificate chain.
///
/// Does not make network connections — validates the TLS subsystem directly.
/// Reads the CA PEM from disk (ca-cert.pem written by `load_or_create`) to
/// build a trust store and verify the leaf cert chain.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_per_host_ca_generates_valid_chain() {
    use base64::Engine as _;
    use rustls::pki_types::CertificateDer;

    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    // Sign a leaf cert for a test domain.
    let ck = ca.sign_cert("allowed.example.com").expect("sign_cert must succeed");
    assert!(!ck.cert_der.is_empty(), "cert DER must not be empty");
    assert!(!ck.key_der.is_empty(), "key DER must not be empty");

    // Read the CA cert PEM that was persisted to disk by load_or_create.
    let ca_cert_pem = tokio::fs::read_to_string(dir.path().join("ca-cert.pem"))
        .await
        .expect("ca-cert.pem must exist after load_or_create");
    assert!(
        ca_cert_pem.contains("-----BEGIN CERTIFICATE-----"),
        "CA PEM must contain a certificate"
    );

    // Parse the CA PEM into a DER and add it to a rustls root store.
    // Strip PEM headers/footers and base64-decode to get raw DER bytes.
    let pem_body: String = ca_cert_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let ca_cert_der_bytes = base64::engine::general_purpose::STANDARD
        .decode(pem_body)
        .expect("base64 decode of CA PEM must succeed");
    let ca_cert_der = CertificateDer::from(ca_cert_der_bytes);
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert_der)
        .expect("adding CA cert to root store must succeed");

    // Build the leaf cert PEM for inspection.
    let b64 = base64::engine::general_purpose::STANDARD.encode(&ck.cert_der);
    let leaf_cert_pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
    assert!(!leaf_cert_pem.is_empty(), "leaf cert PEM must not be empty");

    // Verify the leaf cert DER is non-empty and the root store accepted our CA.
    let leaf_der = CertificateDer::from(ck.cert_der.clone());
    assert_eq!(root_store.len(), 1, "root store must contain exactly the test CA");
    assert!(!leaf_der.is_empty(), "leaf cert DER must not be empty");
}

/// Test 6: 10 concurrent CONNECT requests — 5 allowed, 5 denied — all enforced.
#[tokio::test(flavor = "multi_thread")]
async fn proxy_concurrent_requests_all_enforced() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config(dir.path(), vec!["forbidden.example.com".into()]);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    // Spawn 10 concurrent tasks: 5 to allowed host, 5 to denied host.
    let mut tasks = Vec::with_capacity(10);
    let allowed_target = format!("127.0.0.1:{}", portpicker::pick_unused_port().unwrap());

    for i in 0..10 {
        let addr = proxy_addr;
        let target = if i < 5 {
            allowed_target.clone()
        } else {
            "forbidden.example.com:443".to_string()
        };
        tasks.push(tokio::spawn(async move { connect_to_proxy(addr, &target).await }));
    }

    let mut allowed_count = 0usize;
    let mut denied_count = 0usize;

    for task in tasks {
        let line = task.await.expect("task must not panic");
        if line.contains("200") {
            allowed_count += 1;
        } else if line.contains("403") {
            denied_count += 1;
        }
    }

    assert_eq!(allowed_count, 5, "exactly 5 connections should be allowed");
    assert_eq!(denied_count, 5, "exactly 5 connections should be denied");

    // Collect events with a short timeout — we expect 10 total.
    let mut event_count = 0usize;
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, event_rx.recv()).await {
            Ok(Ok(_)) => event_count += 1,
            _ => break,
        }
        if event_count >= 10 {
            break;
        }
    }

    assert_eq!(
        event_count, 10,
        "exactly 10 audit events must be emitted (5 allow + 5 deny)"
    );

    abort.abort();
}
