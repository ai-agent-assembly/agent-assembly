//! AAASM-1943 / F116 ST-W — Tool Execution Sandbox E2E.
//!
//! Acceptance attestation for spec highlight ④ "Tool Execution Sandbox"
//! (spec line 7283). Covers the **network-egress half** of the highlight
//! end-to-end:
//!
//! * **ST-W-2-allow** — A sandboxed tool's CONNECT to an allowlisted host
//!   succeeds and emits the standard allow audit event.
//! * **ST-W-2-deny** — A sandboxed tool's CONNECT to a non-allowlisted
//!   host is blocked at the proxy boundary (HTTP 403) with zero upstream
//!   contact, and emits a denial audit event.
//!
//! The **filesystem-isolation half** (Scenario 1) is tracked under
//! [AAASM-1965](https://lightning-dust-mite.atlassian.net/browse/AAASM-1965)
//! — the WASM/WASI sandbox runtime that's a 5-7 day implementation. ST-W-1
//! lives below as an `#[ignore]` placeholder so the F116 ST-W coverage
//! matrix can mark the cell visible-but-deferred.
//!
//! ## Why two paired tests for one scenario
//!
//! The allow and deny paths exercise different proxy branches:
//! - Allow → glob match succeeds → tunnel proceeds via the existing
//!   `llm_only` transparent-tunnel path (we test against a local
//!   `TcpListener` standing in for the upstream).
//! - Deny → glob match fails → CONNECT handler returns 403 before any
//!   upstream dial. Verified by a timeout proving the upstream listener
//!   never `accept()`s a connection.

use std::net::SocketAddr;
use std::time::Duration;

use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

fn proxy_config(ca_dir: &std::path::Path, network_allowlist: Vec<String>) -> ProxyConfig {
    let port = portpicker::pick_unused_port().expect("no free port");
    ProxyConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 10,
        llm_only: false,
        denied_hosts: Vec::new(),
        network_allowlist,
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::default(),
        upstream_override: None,
        gateway_endpoint: None,
    }
}

async fn start_proxy(
    config: ProxyConfig,
    ca: CaStore,
) -> (SocketAddr, broadcast::Receiver<PipelineEvent>, tokio::task::AbortHandle) {
    let addr = config.bind_addr;
    let (tx, rx) = broadcast::channel(256);
    let server = aa_proxy::proxy::ProxyServer::new(config, ca, tx);
    let jh = tokio::spawn(async move { server.run().await.unwrap() });
    let abort = jh.abort_handle();

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

// ── ST-W-2 (allow path) ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn st_w_2_network_allowlist_permits_matching_host() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    // Allowlist contains `127.0.0.1` (the local stand-in upstream) plus a
    // distractor pattern that doesn't match. The proxy must permit the
    // CONNECT because at least one pattern matches.
    let allowlist = vec!["127.0.0.1".to_string(), "*.anthropic.com".to_string()];
    let config = proxy_config(dir.path(), allowlist);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    let target = format!("127.0.0.1:{}", portpicker::pick_unused_port().unwrap());
    let response_line = connect_to_proxy(proxy_addr, &target).await;

    assert!(
        response_line.contains("200"),
        "allowlisted host must get 200 Connection Established; got: {response_line}"
    );

    // The proxy emits a NetworkCall audit event on the allow path; the
    // event detail must contain the target host so reviewers can
    // reconstruct what the sandboxed tool reached.
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");
    assert!(matches!(event, PipelineEvent::Audit(_)), "expected Audit event");
    let event_debug = format!("{event:?}");
    assert!(
        event_debug.contains("127.0.0.1"),
        "allow audit must record target host; got: {event_debug}"
    );

    abort.abort();
}

// ── ST-W-2 (deny path) ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn st_w_2_network_allowlist_blocks_non_matching_host() {
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    // Allowlist permits only `api.example.com`. The CONNECT will target
    // a different host, which must be rejected before any upstream dial.
    let allowlist = vec!["api.example.com".to_string()];
    let config = proxy_config(dir.path(), allowlist);
    let (proxy_addr, mut event_rx, abort) = start_proxy(config, ca).await;

    // Bind a real local TcpListener — if the proxy ever dials upstream
    // (incorrectly), the listener's accept() would succeed before our
    // deadline. A timeout on accept() proves the 403 was issued
    // strictly before any upstream contact.
    let upstream_port = portpicker::pick_unused_port().expect("free port");
    let upstream_listener = TcpListener::bind(format!("127.0.0.1:{upstream_port}"))
        .await
        .expect("bind upstream listener");
    let accept_task = tokio::spawn(async move { upstream_listener.accept().await });

    let target = format!("evil.attacker.net:{upstream_port}");
    let response_line = connect_to_proxy(proxy_addr, &target).await;

    assert!(
        response_line.contains("403"),
        "non-allowlisted host must get 403 Forbidden; got: {response_line}"
    );

    // No upstream contact within 200 ms — proves the deny short-circuited
    // before any TCP dial.
    let accept_result = tokio::time::timeout(Duration::from_millis(200), accept_task).await;
    assert!(
        accept_result.is_err(),
        "denied CONNECT must never reach upstream; accept() should have timed out"
    );

    // Deny path also emits an audit event (currently shaped as the same
    // NetworkCall variant as the allow path, with the decision flag set).
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("event within 1s")
        .expect("event received");
    assert!(matches!(event, PipelineEvent::Audit(_)), "expected Audit event");
    let event_debug = format!("{event:?}");
    assert!(
        event_debug.contains("evil.attacker.net"),
        "deny audit must record target host; got: {event_debug}"
    );

    abort.abort();
}

// ── ST-W-1 (filesystem isolation) — deferred to AAASM-1965 ──────────────────

#[tokio::test]
#[ignore = "AAASM-1965: requires WASM/WASI sandbox runtime — aa-wasm is currently a 5-line stub"]
async fn st_w_1_filesystem_isolation_for_sandboxed_tools() {
    // When AAASM-1965 ships:
    //
    // 1. Register a WASM-runnable tool that does `read_file("/etc/passwd")`.
    // 2. Configure the sandbox with a filesystem allowlist that includes
    //    `/tmp/sandbox-root/` but NOT `/etc/`.
    // 3. Drive a `tools/call` invoking the tool.
    // 4. Assert: the tool's WASI `path_open` returns `EACCES` for
    //    `/etc/passwd`; the tool either fails or returns redacted/empty
    //    content.
    // 5. Assert: the audit chain records the blocked filesystem read with
    //    the requested path + the `EACCES` outcome.
    //
    // Placeholder kept here so the F116 ST-W acceptance matrix has a
    // visible-but-deferred cell pointing at the follow-up Story.
    unimplemented!("AAASM-1965 — see https://lightning-dust-mite.atlassian.net/browse/AAASM-1965");
}
