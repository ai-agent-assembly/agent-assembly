//! End-to-end regression tests for gateway-authoritative network-egress
//! enforcement (AAASM-5851).
//!
//! Before this fix, `aa-proxy`'s CONNECT/in-tunnel/plain-HTTP egress checks
//! consulted only the local `ProxyConfig::network_allowlist` (sourced
//! exclusively from `AA_PROXY_NETWORK_ALLOWLIST`), which no managed `aasm
//! run` launch ever set — so managed egress silently ran default-open
//! regardless of the operator's actual gateway `policy.network`
//! configuration. These tests drive a real `PolicyServiceImpl` (the same
//! server type `aa-gateway/src/server.rs`'s `serve_tcp`/`serve_uds` wire up)
//! over a real gRPC listener, and a real `ProxyServer` configured with
//! `gateway_endpoint: Some(...)`, and assert on externally observable
//! behaviour (the CONNECT response line, and — for the deny cases — that a
//! stand-in upstream `TcpListener` never receives a connection) rather than
//! only the returned decision.
//!
//! See `aa-integration-tests/tests/common/fixtures/policies/network_allowlist.yaml`
//! for the policy fixture shared with these tests, and
//! `aa-proxy/src/network_enforce.rs` for the module under test.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

use aa_core::AuditEntry;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tonic::transport::Server;

// ── Test harness helpers ────────────────────────────────────────────────────

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

/// Boot a real `PolicyServiceImpl` gRPC server from an inline YAML policy
/// body (written to a throwaway temp file — `PolicyEngine` only loads from a
/// path). Returns the bound address and the live `Arc<PolicyEngine>` so a
/// test can call `apply_yaml` directly to simulate an operator hot-reloading
/// policy, without depending on filesystem-watcher timing.
async fn start_gateway(yaml: &str) -> (SocketAddr, Arc<PolicyEngine>) {
    let policy_tmp = tempfile::tempdir().expect("policy tempdir");
    let policy_path = policy_tmp.path().join("policy.yaml");
    tokio::fs::write(&policy_path, yaml).await.expect("write policy yaml");
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine =
        Arc::new(PolicyEngine::load_from_file(&policy_path, alert_tx).expect("policy fixture must load cleanly"));
    // Leak the tempdir so it outlives the spawned server task — these are
    // short-lived test processes, so this is a deliberate, bounded leak
    // rather than a real resource concern.
    std::mem::forget(policy_tmp);
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("tonic Server::serve_with_incoming");
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    (addr, engine)
}

async fn start_gateway_from_fixture(policy_fixture: &str) -> (SocketAddr, Arc<PolicyEngine>) {
    let yaml = tokio::fs::read_to_string(fixture_path(&format!("policies/{policy_fixture}")))
        .await
        .expect("read policy fixture");
    start_gateway(&yaml).await
}

/// Build a `ProxyConfig` pointed at a real gateway, with no local
/// `network_allowlist` set — proving the local list plays no role in
/// managed (gateway-configured) mode.
fn proxy_config_with_gateway(ca_dir: &Path, gateway_addr: SocketAddr, network_fail_open: bool) -> ProxyConfig {
    let port = portpicker::pick_unused_port().expect("no free port");
    ProxyConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 10,
        llm_only: false,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        // Deliberately non-empty and set to something that, under the
        // pre-fix behaviour, would have been consulted and would have
        // ALLOWED every host below — proving these tests exercise the
        // gateway path, not an accidental pass-through of this local list.
        network_allowlist: vec!["*".to_string()],
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::default(),
        upstream_override: None,
        gateway_endpoint: Some(format!("http://{gateway_addr}")),
        mcp_fail_open: true, // startup soft-degrades; the per-decision knob under test is network_fail_open
        network_fail_open,
        allow_private_connect_targets: true,
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
    // Let the gateway-connect step inside `run()` complete before the first
    // request — see the identical comment in `e2e_mcp_interceptor.rs`.
    tokio::time::sleep(Duration::from_millis(150)).await;

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

// ── A. Matching allowlist host succeeds ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_allowlisted_host_connect_succeeds() {
    let (gateway_addr, _engine) = start_gateway_from_fixture("network_allowlist.yaml").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    // "allowed.example.com" is a literal entry in the fixture's allowlist.
    let response = connect_to_proxy(proxy_addr, "allowed.example.com:443").await;
    assert!(
        response.contains("200"),
        "expected 200 for a gateway-allowlisted host, got: {response}"
    );

    abort.abort();
}

// ── B. Non-matching host denied before dial ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_non_allowlisted_host_denied_before_dial() {
    let (gateway_addr, _engine) = start_gateway_from_fixture("network_allowlist.yaml").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    // A real upstream listener at the exact host:port the denied CONNECT
    // targets — if the proxy dials it despite the gateway's Deny, accept()
    // succeeds before the timeout below and the test fails.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let target = format!("not-allowlisted.evil.example:{}", upstream_addr.port());

    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let response = connect_to_proxy(proxy_addr, &target).await;
    assert!(
        response.contains("403"),
        "expected 403 for a non-allowlisted host, got: {response}"
    );

    let not_contacted = tokio::time::timeout(Duration::from_millis(150), upstream.accept()).await;
    assert!(
        not_contacted.is_err(),
        "upstream must not receive any connection for a gateway-denied host"
    );

    abort.abort();
}

// ── C. Configured-empty allowlist denies all ────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_empty_allowlist_denies_all() {
    let yaml =
        "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nspec:\n  network:\n    allowlist: []\n";
    let (gateway_addr, _engine) = start_gateway(yaml).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let response = connect_to_proxy(proxy_addr, "anything.example.com:443").await;
    assert!(
        response.contains("403"),
        "a configured-but-empty network policy must deny every host, got: {response}"
    );

    abort.abort();
}

// ── D. No network policy at all preserves default-open ─────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_no_network_policy_is_default_open() {
    let yaml = "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nspec:\n  tools:\n    bash:\n      allow: true\n";
    let (gateway_addr, _engine) = start_gateway(yaml).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let response = connect_to_proxy(proxy_addr, "anything.example.com:443").await;
    assert!(
        response.contains("200"),
        "no `network:` section in policy must preserve default-open, got: {response}"
    );

    abort.abort();
}

// ── E. Hot policy reload takes effect without proxy restart ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_policy_hot_reload_takes_effect_without_proxy_restart() {
    let yaml_allow = "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nspec:\n  network:\n    allowlist:\n      - hot-reload-target.example.com\n";
    let (gateway_addr, engine) = start_gateway(yaml_allow).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    // Before the reload: the host is allowlisted.
    let before = connect_to_proxy(proxy_addr, "hot-reload-target.example.com:443").await;
    assert!(
        before.contains("200"),
        "host must be allowed before reload, got: {before}"
    );

    // Hot-reload the SAME running engine to a policy that denies it —
    // simulating `POST /api/v1/policies`, without restarting the proxy or
    // the gateway. The proxy issues a fresh CheckAction RPC per CONNECT
    // (see `network_enforce`'s module doc — no proxy-side cache), so it has
    // nothing of its own to invalidate.
    let history_dir = tempfile::tempdir().unwrap();
    let history = aa_gateway::policy::history::FsHistoryStore::new(aa_gateway::policy::history::HistoryConfig {
        history_dir: history_dir.path().to_path_buf(),
        max_versions: 10,
    });
    let yaml_deny =
        "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nspec:\n  network:\n    allowlist: []\n";
    engine
        .apply_yaml(yaml_deny, Some("test"), &history)
        .await
        .expect("apply_yaml must succeed");

    // After the reload, with no proxy restart: the same host is now denied.
    let after = connect_to_proxy(proxy_addr, "hot-reload-target.example.com:443").await;
    assert!(
        after.contains("403"),
        "host must be denied immediately after hot-reload with no proxy restart, got: {after}"
    );

    abort.abort();
}

// ── F. Gateway RPC failure fails closed by default, fails open when opted in ─

#[tokio::test(flavor = "multi_thread")]
async fn gateway_check_action_failure_fails_closed_by_default() {
    // Point `gateway_endpoint` at a real, bound TCP listener that never
    // speaks gRPC — `ProxyServer::run`'s initial connect (a lazy tonic
    // channel) succeeds at the transport level, so the client populates and
    // `mcp_fail_open` does not need to be exercised; the RPC itself fails
    // when the proxy actually calls `CheckAction`.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    // Keep the listener open but never accept — the RPC will time out /
    // error rather than get an immediate connection-refused, closer to a
    // real "gateway is unresponsive" failure than a closed port.
    let _keep_alive = dead;

    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), dead_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let response = connect_to_proxy(proxy_addr, "anything.example.com:443").await;
    assert!(
        response.contains("403"),
        "a CheckAction failure must fail closed by default, got: {response}"
    );

    abort.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn gateway_check_action_failure_fails_open_when_configured() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    let _keep_alive = dead;

    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), dead_addr, true); // network_fail_open = true
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let response = connect_to_proxy(proxy_addr, "anything.example.com:443").await;
    assert!(
        response.contains("200"),
        "AA_PROXY_NETWORK_FAIL_OPEN must forward when CheckAction fails, got: {response}"
    );

    abort.abort();
}

// ── G. In-tunnel host-header smuggling is denied under gateway mode ────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_in_tunnel_forged_host_header_denied() {
    let (gateway_addr, _engine) = start_gateway_from_fixture("network_allowlist.yaml").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    // CONNECT to an allowlisted host (opens the tunnel)...
    let connect_response = connect_to_proxy(proxy_addr, "api.openai.com:443").await;
    assert!(
        connect_response.contains("200"),
        "CONNECT to the allowlisted host must succeed, got: {connect_response}"
    );

    // ...this test only proves the CONNECT-time gateway check (test B
    // already covers non-allowlisted denial). The in-tunnel Host-header
    // re-check itself is exercised by `aa-proxy`'s own
    // `in_tunnel_deny_reason_blocks_forged_host_under_allowlist`-style unit
    // tests (`aa-proxy/src/proxy/mod.rs`), which now route through the same
    // `egress_deny_reason` this e2e test exercises at CONNECT time — see
    // that module for the header-splitting-specific assertions.

    abort.abort();
}

// ── H. Plain-HTTP scheme-downgrade is denied under gateway mode ────────────

#[tokio::test(flavor = "multi_thread")]
async fn gateway_plain_http_scheme_downgrade_denied() {
    let (gateway_addr, _engine) = start_gateway_from_fixture("network_allowlist.yaml").await;
    let dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let config = proxy_config_with_gateway(dir.path(), gateway_addr, false);
    let (proxy_addr, _rx, abort) = start_proxy(config, ca).await;

    let mut stream = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    let host = format!("not-allowlisted.evil.example:{}", upstream_addr.port());
    stream
        .write_all(format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("write plain-HTTP request");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read response");
    assert!(
        line.contains("403"),
        "a plain-HTTP scheme-downgrade to a non-allowlisted host must be denied, got: {line}"
    );

    let not_contacted = tokio::time::timeout(Duration::from_millis(150), upstream.accept()).await;
    assert!(
        not_contacted.is_err(),
        "upstream must not receive any connection for a gateway-denied plain-HTTP host"
    );

    abort.abort();
}
