//! F116 ST-I — E2E secret-value interception (detection slice).
//!
//! Exercises the live credential scanner inside `aa_gateway::PolicyEngine` by
//! evaluating governance actions whose `args` payload embeds a synthetic API
//! key, GitHub PAT, OpenAI key, or a custom policy-defined pattern. Asserts:
//!
//! 1. The decision stays `Allow` (the scanner redacts in-memory, it does not
//!    deny on its own — see `aa-gateway/src/engine/mod.rs:471` Stage 6).
//! 2. `credential_findings` is non-empty and carries the expected
//!    `CredentialKind`.
//! 3. `redacted_payload` is `Some(_)` and contains the `[REDACTED:<kind>]`
//!    label.
//! 4. The full original secret never appears in `redacted_payload`.
//!
//! ## Scope
//!
//! This file ships the **detection-only** slice of the original 8-test ST.
//! The remaining tests in the ST require runtime features that are not yet
//! implemented (audit-log emission of credential findings, alert emission
//! with severity=critical, policy action modes `block` / `redact_only`,
//! mock LLM upstream). See AAASM-1544 / 1545 / 1546 / 1547 for the follow-up
//! work; the corresponding tests will be added in a second PR once those
//! runtime features land.
//!
//! ## ST-N proxy-path slice (AAASM-1549)
//!
//! The `mod proxy_path` block at the end of this file is the Layer 2
//! counterpart to the SDK/gateway slice above. It drives
//! `aa_proxy::intercept::Interceptor` directly with OpenAI-shaped request
//! bodies and asserts:
//!
//! 1. The proxy's default `CredentialScanner` detects AWS access keys in
//!    the body shapes the proxy will see in production and redacts them
//!    into `[REDACTED:AwsAccessKey]` markers.
//! 2. No raw secret ever appears in an emitted `PipelineEvent::Audit`
//!    when multiple secret kinds are present in a single body.
//! 3. Short high-entropy strings below the `GenericHighEntropy` floor do
//!    not produce findings (no alert fatigue).
//!
//! The data-path assertions in ST-N's original spec
//! (`proxy_aws_key_in_body_redacted_before_forwarding`,
//! `proxy_secret_block_policy_prevents_forwarding`,
//! `proxy_secret_redact_only_credential_findings_in_audit`) require body
//! parsing inside the MitM tunnel, `credential_action` enforcement on
//! flowing bytes, and audit-JSONL writer wiring — none of which exist in
//! `aa-proxy` today. See **AAASM-1566** for the data-path follow-up that
//! will land those features and the corresponding E2E tests.
//!
//! ## Synthetic secrets only
//!
//! Every secret value below is synthetic — from AWS public-docs examples
//! (`AKIAIOSFODNN7EXAMPLE`), from prefixes documented as test-only
//! (`sk-test-`), or manually-fabricated padding (`ghp_0000…`). No real
//! secrets are stored in this fixture.

use std::collections::BTreeMap;
use std::path::Path;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, CredentialKind, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::{EvaluationResult, PolicyEngine};

// ── Synthetic secret fixtures ────────────────────────────────────────────────

/// AWS access key ID from AWS public documentation. Synthetic.
const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// GitHub personal access token prefix + zero-padding. Synthetic.
const FAKE_GITHUB_PAT: &str = "ghp_0000000000000000000000000000000000";

/// OpenAI key with the documented `sk-test-` test prefix. Synthetic.
const FAKE_OPENAI_KEY: &str = "sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890";

/// Custom-pattern token shaped to match `MYCO-SECRET-[A-Za-z0-9]+`.
const FAKE_CUSTOM_TOKEN: &str = "MYCO-SECRET-DEADBEEFCAFE0001";

/// Below the `GenericHighEntropy` length floor (20 chars) — must not trip the
/// scanner. 12 alphanumeric characters with no built-in prefix match.
const SHORT_HIGH_ENTROPY: &str = "abc123def456";

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve a fixture path relative to this crate's manifest root.
fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

/// Build a minimal `AgentContext` for tests. The 16-byte agent ID seed is
/// passed in so each test can produce a distinct, deterministic identity.
fn make_ctx(agent_bytes: [u8; 16]) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(agent_bytes),
        session_id: SessionId::from_bytes([0xAAu8; 16]),
        pid: 1,
        started_at: Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

/// Construct a `PolicyEngine` from the F116 ST-I secret-detection fixture.
fn make_engine() -> PolicyEngine {
    let path = fixture_path("policies/secret_detection_patterns.yaml");
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(&path, tx).expect("secret_detection_patterns.yaml must load cleanly")
}

/// Build a `ToolCall` action against the policy-allowed `test_tool` whose
/// `args` payload is the supplied string. Stage 6 of `evaluate()` scans the
/// `args` field; see `aa-gateway/src/engine/mod.rs:478`.
fn tool_call_with_args(args: impl Into<String>) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: "test_tool".to_string(),
        args: args.into(),
    }
}

/// Evaluate `action` with a fresh engine and a deterministic agent identity.
fn evaluate(action: &GovernanceAction, agent_seed: u8) -> EvaluationResult {
    let engine = make_engine();
    let ctx = make_ctx([agent_seed; 16]);
    engine.evaluate(&ctx, action)
}

/// Helper for the no-false-positive expectations: asserts `Allow` and clean
/// scan output. Used by the negative-path test below.
fn assert_clean(result: &EvaluationResult) {
    assert_eq!(result.decision, PolicyResult::Allow, "clean payload must yield Allow");
    assert!(
        result.credential_findings.is_empty(),
        "clean payload must produce no credential findings, got {:?}",
        result.credential_findings,
    );
    assert!(
        result.redacted_payload.is_none(),
        "clean payload must leave redacted_payload as None",
    );
}

/// Helper for the positive-path expectations: asserts a single finding of the
/// expected `CredentialKind` and a non-None `redacted_payload`. Used by every
/// detection test below.
fn assert_detected(result: &EvaluationResult, expected: CredentialKind) {
    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "scanner-only detection must not deny — decision should remain Allow",
    );
    assert!(
        result.credential_findings.iter().any(|f| f.kind == expected),
        "expected at least one finding of kind {:?}, got {:?}",
        expected,
        result.credential_findings,
    );
    assert!(
        result.redacted_payload.is_some(),
        "detection must populate redacted_payload",
    );
}

// ── Test 1 — AWS access key in tool args ─────────────────────────────────────

#[test]
fn aws_access_key_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"data":"my access key is {FAKE_AWS_ACCESS_KEY}, rotate soon"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA1);

    assert_detected(&result, CredentialKind::AwsAccessKey);

    let redacted = result
        .redacted_payload
        .expect("AWS access key must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:AwsAccessKey]"),
        "redacted payload must carry the [REDACTED:AwsAccessKey] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_AWS_ACCESS_KEY),
        "redacted payload must not retain the original AWS access key",
    );
}

// ── Test 2 — GitHub personal access token in tool args ───────────────────────

#[test]
fn github_pat_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"headers":{{"X-Auth":"Bearer {FAKE_GITHUB_PAT}"}}}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA2);

    assert_detected(&result, CredentialKind::GitHubPat);

    let redacted = result
        .redacted_payload
        .expect("GitHub PAT must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:GitHubPat]"),
        "redacted payload must carry the [REDACTED:GitHubPat] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_GITHUB_PAT),
        "redacted payload must not retain the original GitHub PAT",
    );
}

// ── Test 3 — OpenAI key in tool args ─────────────────────────────────────────

#[test]
fn openai_key_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"messages":[{{"role":"user","content":"my key is {FAKE_OPENAI_KEY}"}}]}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA3);

    assert_detected(&result, CredentialKind::OpenAiKey);

    let redacted = result
        .redacted_payload
        .expect("OpenAI key must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:OpenAiKey]"),
        "redacted payload must carry the [REDACTED:OpenAiKey] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_OPENAI_KEY),
        "redacted payload must not retain the original OpenAI key",
    );
}

// ── Test 4 — Policy-defined custom regex in tool args ────────────────────────

#[test]
fn custom_sensitive_pattern_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"data":"internal token = {FAKE_CUSTOM_TOKEN}"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA4);

    assert_detected(&result, CredentialKind::Custom);

    let redacted = result
        .redacted_payload
        .expect("custom-regex match must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:Custom]"),
        "redacted payload must carry the [REDACTED:Custom] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_CUSTOM_TOKEN),
        "redacted payload must not retain the original custom token",
    );
}

// ── Test 5 — No false positive on short high-entropy string ──────────────────

#[test]
fn short_high_entropy_string_does_not_trigger_scanner() {
    // 12 alphanumeric characters: no AC-literal prefix matches, and the value
    // is below the 20-byte length floor enforced for `GenericHighEntropy`.
    // This guards against alert fatigue (AAASM-1521 acceptance criterion).
    let payload = format!(r#"{{"id":"{SHORT_HIGH_ENTROPY}"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA5);

    assert_clean(&result);
}

// ── Test 6 — Critical security assertion: raw secrets never in redacted output

#[test]
fn redacted_payload_never_contains_any_raw_secret() {
    // Combine four independent secrets in one payload so a single evaluation
    // exercises the multi-finding redaction path. The flagship security
    // invariant for this ST: even one byte of an original secret leaking
    // through is a hard failure.
    //
    // The scanner runs four passes (AC literal, digit sequences, emails,
    // high-entropy). Overlapping findings between passes can produce
    // garbled [REDACTED:Kind] labels in the output — see the engine's
    // `ScanResult::redact()` for reverse-offset replacement semantics.
    // That is acceptable: the redaction primitive's only contract is that
    // raw secret bytes are removed. Asserting on specific label shapes
    // under overlap would be brittle, so this test asserts only the
    // security invariant.
    let payload = format!(
        r#"{{
            "aws": "{FAKE_AWS_ACCESS_KEY}",
            "openai": "{FAKE_OPENAI_KEY}",
            "github": "{FAKE_GITHUB_PAT}",
            "custom": "{FAKE_CUSTOM_TOKEN}"
        }}"#
    );
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA6);

    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "scanner-only detection must not deny",
    );
    assert!(
        result.credential_findings.len() >= 4,
        "expected at least one finding per embedded secret (>=4); got {:?}",
        result.credential_findings,
    );

    let redacted = result
        .redacted_payload
        .expect("multi-secret payload must produce a redacted output");

    // Primary security invariant: NO raw secret string appears in the redacted output.
    for (label, raw) in [
        ("AWS access key", FAKE_AWS_ACCESS_KEY),
        ("OpenAI key", FAKE_OPENAI_KEY),
        ("GitHub PAT", FAKE_GITHUB_PAT),
        ("custom token", FAKE_CUSTOM_TOKEN),
    ] {
        assert!(
            !redacted.contains(raw),
            "SECURITY INVARIANT VIOLATED: {label} appears in redacted payload — value would leak to downstream audit / alert / upstream",
        );
    }

    // Sanity check: at least one redaction marker was emitted somewhere in the
    // output. The specific kind / count is not asserted because overlapping
    // findings can collapse adjacent markers under the current redact() logic.
    assert!(
        redacted.contains("[REDACTED:"),
        "redacted payload must contain at least one [REDACTED:Kind] marker, got: {redacted}",
    );
}

// ── Proxy data-path E2E (AAASM-1566) ─────────────────────────────────────────
//
// These tests drive a real `aa_proxy::proxy::ProxyServer` end-to-end: a
// reqwest-shaped client opens a CONNECT tunnel through the proxy to an LLM
// hostname, the proxy MitM-terminates, runs `intercept_request` against the
// real body bytes, and applies the configured `CredentialAction`. The
// upstream is a small TLS-terminating mock the proxy dials via the
// `upstream_override` test knob (so we don't have to hijack DNS to redirect
// `api.openai.com:443` to `127.0.0.1:<port>`).
//
// The three tests below match AAASM-1566 acceptance criteria 1:1 — see the
// ticket body for the spec.

mod proxy_data_path {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::Engine as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{broadcast, mpsc};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use aa_proxy::audit_jsonl::ProxyAuditEntry;
    use aa_proxy::config::{CredentialAction, ProxyConfig};
    use aa_proxy::proxy::ProxyServer;
    use aa_proxy::tls::CaStore;
    use aa_runtime::pipeline::PipelineEvent;

    /// LLM hostname the client CONNECTs to. `detect_api` returns
    /// `LlmApiPattern::OpenAi`, which is what triggers the proxy's
    /// body-inspection branch.
    const LLM_HOSTNAME: &str = "api.openai.com";

    /// Install rustls's default crypto provider exactly once per process.
    /// Both `aws-lc-rs` and `ring` are present transitively in this
    /// workspace, so rustls 0.23 refuses to pick one automatically — see
    /// `project_rustls_crypto_provider`.
    fn install_crypto_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// In-process TLS-terminating HTTP upstream that records inbound request
    /// bodies and replies with a canned chat-completion envelope.
    struct TlsCapturingUpstream {
        addr: SocketAddr,
        history: Arc<Mutex<Vec<Vec<u8>>>>,
        _abort: tokio::task::AbortHandle,
    }

    impl TlsCapturingUpstream {
        fn request_count(&self) -> usize {
            self.history.lock().expect("history mutex poisoned").len()
        }

        fn last_body(&self) -> Option<String> {
            self.history
                .lock()
                .expect("history mutex poisoned")
                .last()
                .and_then(|b| std::str::from_utf8(b).ok().map(String::from))
        }

        /// Start a TLS-terminating capture upstream signed by the proxy's CA.
        ///
        /// The certificate is signed for `LLM_HOSTNAME` so when the proxy's
        /// client connects with `ServerName::try_from("api.openai.com")` the
        /// server name matches the cert. Combined with the proxy's
        /// `skip_upstream_tls_verify=true` this lets us assert end-to-end
        /// flow without installing the test CA in the system trust store.
        async fn start(ca: &CaStore) -> Self {
            let ck = ca.sign_cert(LLM_HOSTNAME).expect("ca sign_cert");
            let cert = CertificateDer::from(ck.cert_der.clone());
            let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
            let acceptor = TlsAcceptor::from(Arc::new(server_config));

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
            let addr = listener.local_addr().expect("local_addr");

            let history: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let h_arc = Arc::clone(&history);

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let history = Arc::clone(&h_arc);
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut buf: Vec<u8> = Vec::new();
                        let mut tmp = [0u8; 4096];
                        // Read until \r\n\r\n separator.
                        let head_end = loop {
                            match tls.read(&mut tmp).await {
                                Ok(0) => return,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => return,
                            }
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p;
                            }
                        };
                        // Parse Content-Length.
                        let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                        let cl: usize = head
                            .lines()
                            .find_map(|line| {
                                let lower = line.to_ascii_lowercase();
                                lower
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse().ok())
                            })
                            .unwrap_or(0);
                        let body_start = head_end + 4;
                        // Read remaining body bytes.
                        while buf.len() < body_start + cl {
                            match tls.read(&mut tmp).await {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => break,
                            }
                        }
                        let body = buf[body_start..body_start + cl].to_vec();
                        history.lock().expect("history mutex poisoned").push(body);
                        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: application/json\r\n\r\n{\"id\":\"mock\"}";
                        let _ = tls.write_all(resp).await;
                        let _ = tls.flush().await;
                    });
                }
            });

            Self {
                addr,
                history,
                _abort: handle.abort_handle(),
            }
        }
    }

    /// Build a [`ClientConfig`] that trusts the proxy's per-host CA (so
    /// `ServerName = LLM_HOSTNAME` verifies against the MitM-issued leaf cert).
    async fn client_trust_proxy_ca(ca_dir: &std::path::Path) -> ClientConfig {
        let pem = tokio::fs::read_to_string(ca_dir.join("ca-cert.pem"))
            .await
            .expect("read ca cert pem");
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("decode ca pem base64");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(der_bytes))
            .expect("add ca cert to root store");
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// Spin up a `ProxyServer` with the supplied `credential_action` and
    /// `upstream_override`, returning the proxy's bound address plus an
    /// abort handle and the receive channel.
    async fn start_proxy(
        ca_dir: &std::path::Path,
        ca: CaStore,
        credential_action: CredentialAction,
        upstream_override: SocketAddr,
        audit_jsonl_tx: Option<mpsc::Sender<ProxyAuditEntry>>,
    ) -> (SocketAddr, broadcast::Receiver<PipelineEvent>, tokio::task::AbortHandle) {
        let port = portpicker::pick_unused_port().expect("free port");
        let config = ProxyConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            ca_dir: ca_dir.to_path_buf(),
            cert_cache_capacity: 10,
            llm_only: false,
            denied_hosts: Vec::new(),
            skip_upstream_tls_verify: true,
            credential_action,
            upstream_override: Some(upstream_override),
        };
        let bind_addr = config.bind_addr;
        let (tx, rx) = broadcast::channel(64);
        let server = ProxyServer::new_with_audit_sink(config, ca, tx, audit_jsonl_tx);
        let jh = tokio::spawn(async move { server.run().await.unwrap() });
        let abort = jh.abort_handle();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("proxy did not start on {bind_addr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (bind_addr, rx, abort)
    }

    /// Drive an HTTPS request through the proxy to the LLM hostname,
    /// returning the CONNECT status line and (optionally) the inner response
    /// status. Block-mode tests assert on the CONNECT response status line;
    /// successful tests verify the upstream observed the call.
    async fn send_through_proxy(
        proxy_addr: SocketAddr,
        client_config: Arc<ClientConfig>,
        body: &str,
    ) -> ProxyDriveResult {
        let mut tcp = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
        let target_port = 443; // Arbitrary — upstream_override forwards regardless.
        let target = format!("{LLM_HOSTNAME}:{target_port}");
        let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).await.expect("write CONNECT");

        let mut reader = BufReader::new(tcp);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.expect("read connect status");
        // Drain headers.
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).await.expect("read header line");
            if h.trim().is_empty() {
                break;
            }
        }

        // If the proxy returned a non-200 here (e.g. CONNECT-level deny), we
        // never get to send the inner request — caller asserts on status.
        if !status_line.contains("200") {
            return ProxyDriveResult {
                connect_status: status_line,
                inner_response: None,
            };
        }

        // TLS-wrap the tunnel using the proxy's CA.
        let server_name = ServerName::try_from(LLM_HOSTNAME.to_string()).expect("server name");
        let connector = TlsConnector::from(client_config);
        let tcp = reader.into_inner();
        let mut tls = match connector.connect(server_name, tcp).await {
            Ok(t) => t,
            Err(e) => {
                return ProxyDriveResult {
                    connect_status: status_line,
                    inner_response: Some(format!("TLS error: {e}")),
                };
            }
        };

        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOSTNAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        if let Err(e) = tls.write_all(req.as_bytes()).await {
            return ProxyDriveResult {
                connect_status: status_line,
                inner_response: Some(format!("write error: {e}")),
            };
        }
        // Read response (best-effort) — Block path never reaches here.
        let mut response_buf = vec![0u8; 1024];
        let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut response_buf)).await;
        let response = String::from_utf8_lossy(&response_buf)
            .trim_end_matches('\0')
            .to_string();
        ProxyDriveResult {
            connect_status: status_line,
            inner_response: Some(response),
        }
    }

    /// Result of driving a request through the proxy.
    struct ProxyDriveResult {
        /// CONNECT response status line, e.g. `"HTTP/1.1 200 Connection Established"`.
        connect_status: String,
        /// Inner HTTP response, or `None` when the CONNECT itself was rejected.
        ///
        /// Read by `proxy_secret_block_policy_prevents_forwarding` in the
        /// next commit; allow(dead_code) for the redact-only test that does
        /// not consume it.
        #[allow(dead_code)]
        inner_response: Option<String>,
    }

    // ── Test 1 — redact_only forwards [REDACTED] form, never the raw key ─

    /// `TlsCapturingUpstream::last_body()` contains `[REDACTED:AwsAccessKey]`,
    /// never the raw key. Drives AAASM-1566 acceptance criterion
    /// `proxy_aws_key_in_body_redacted_before_forwarding`.
    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_aws_key_in_body_redacted_before_forwarding() {
        install_crypto_provider();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
        let client_config = Arc::new(client_trust_proxy_ca(dir.path()).await);

        let upstream = TlsCapturingUpstream::start(&ca).await;
        let (proxy_addr, _rx, abort) =
            start_proxy(dir.path(), ca, CredentialAction::RedactOnly, upstream.addr, None).await;

        let body = format!(
            r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"my key is {}"}}]}}"#,
            super::FAKE_AWS_ACCESS_KEY,
        );
        let result = send_through_proxy(proxy_addr, client_config, &body).await;
        assert!(
            result.connect_status.contains("200"),
            "CONNECT must succeed for redact_only, got: {}",
            result.connect_status,
        );

        // Allow the upstream a beat to capture the request.
        for _ in 0..50 {
            if upstream.request_count() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        assert_eq!(
            upstream.request_count(),
            1,
            "upstream must receive exactly one forwarded request",
        );
        let received = upstream.last_body().expect("upstream captured body");
        assert!(
            received.contains("[REDACTED:AwsAccessKey]"),
            "forwarded body must carry the [REDACTED:AwsAccessKey] marker; got: {received}",
        );
        assert!(
            !received.contains(super::FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT: raw AWS key reached upstream — got: {received}",
        );

        abort.abort();
    }

    // ── Test 2 — block policy returns 403 and never dials upstream ───────

    /// Under `CredentialAction::Block` the proxy refuses to forward a body
    /// that contains a detected secret. Asserts both halves of the AC:
    ///
    /// 1. `TlsCapturingUpstream.request_count() == 0` — the proxy never
    ///    dialled upstream.
    /// 2. The inner HTTP response is `HTTP/1.1 403 Forbidden` (the proxy
    ///    writes 403 to the client TLS stream after running the scanner).
    ///
    /// Drives AAASM-1566's `proxy_secret_block_policy_prevents_forwarding`.
    #[tokio::test(flavor = "multi_thread")]
    async fn proxy_secret_block_policy_prevents_forwarding() {
        install_crypto_provider();
        let dir = tempfile::TempDir::new().expect("tempdir");
        let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
        let client_config = Arc::new(client_trust_proxy_ca(dir.path()).await);

        let upstream = TlsCapturingUpstream::start(&ca).await;
        let (proxy_addr, _rx, abort) = start_proxy(dir.path(), ca, CredentialAction::Block, upstream.addr, None).await;

        let body = format!(
            r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"my key is {}"}}]}}"#,
            super::FAKE_AWS_ACCESS_KEY,
        );
        let result = send_through_proxy(proxy_addr, client_config, &body).await;

        // CONNECT-level handshake still succeeds — the proxy only blocks
        // after reading the inner request body inside the tunnel.
        assert!(
            result.connect_status.contains("200"),
            "CONNECT must succeed (block fires inside the TLS tunnel); got: {}",
            result.connect_status,
        );

        let inner = result.inner_response.expect("inner_response must be Some");
        assert!(
            inner.contains("403"),
            "proxy must return 403 inside the tunnel under credential_action=Block; got: {inner:?}",
        );

        // Hard wait to give the upstream a chance to be (incorrectly) dialled.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            upstream.request_count(),
            0,
            "SECURITY INVARIANT: upstream must receive zero requests under Block policy",
        );

        abort.abort();
    }
}

// ── Proxy-path scanner-only slice (AAASM-1549 / ST-N) ────────────────────────
//
// The mod above is the full data-path E2E. The mod below is the older
// scanner-only slice that drives `aa_proxy::Interceptor` directly.

mod proxy_path {
    use std::time::SystemTime;

    use bytes::Bytes;

    use aa_proxy::intercept::detect::LlmApiPattern;
    use aa_proxy::intercept::event::ProxyEvent;

    /// Build an OpenAI-shaped POST body whose `messages[0].content` embeds the
    /// supplied `payload` substring. Mirrors what an agent's `requests` /
    /// `httpx` POST to `https://api.openai.com/v1/chat/completions` looks like
    /// when no SDK is installed (Layer 2 is the only catch).
    pub(super) fn openai_chat_body(payload: &str) -> Bytes {
        Bytes::from(format!(
            r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"{payload}"}}]}}"#
        ))
    }

    /// Construct a `ProxyEvent` carrying an OpenAI-pattern request body. No
    /// response body — this mirrors the moment after the proxy has parsed the
    /// inbound request and is about to forward it upstream.
    pub(super) fn proxy_event_with_request_body(body: Bytes) -> ProxyEvent {
        ProxyEvent {
            agent_id: Some("proxy-path-test".into()),
            pattern: LlmApiPattern::OpenAi,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            request_body: Some(body),
            response_body: None,
            timestamp: SystemTime::now(),
        }
    }

    // ── Test 1 — AWS access key in a proxy-path body ─────────────────────────

    /// The proxy's `Interceptor` redacts any AWS access key embedded in an
    /// intercepted body via its default `CredentialScanner`. Two assertions:
    ///
    /// 1. The same scanner the proxy uses (`CredentialScanner::new()`, see
    ///    `aa-proxy/src/intercept/mod.rs:37`) produces an `AwsAccessKey`
    ///    finding and a `[REDACTED:AwsAccessKey]`-bearing redaction when fed
    ///    the OpenAI request body shape the proxy will see in production.
    ///
    /// 2. Driving `Interceptor::intercept()` end-to-end with that body emits
    ///    a `PipelineEvent::Audit` whose `Debug` repr never contains the raw
    ///    AWS key. This is the security invariant — any leak in the proxy's
    ///    audit emission would expose the secret to downstream subscribers.
    #[tokio::test]
    async fn aws_key_in_proxy_intercepted_body_is_redacted() {
        use aa_core::{CredentialKind, CredentialScanner};
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!("my access key is {key}", key = super::FAKE_AWS_ACCESS_KEY));
        let body_str = std::str::from_utf8(&body).expect("body must be UTF-8 ASCII");

        // (1) Scanner-level proof: the proxy's default scanner finds + redacts
        //     the AWS key in this exact body shape.
        let scan = CredentialScanner::new().scan(body_str);
        assert!(
            scan.findings.iter().any(|f| f.kind == CredentialKind::AwsAccessKey),
            "default scanner must find AwsAccessKey in proxy body shape, got {:?}",
            scan.findings,
        );
        let redacted = scan.redact(body_str);
        assert!(
            redacted.contains("[REDACTED:AwsAccessKey]"),
            "redacted proxy body must carry the [REDACTED:AwsAccessKey] marker, got: {redacted}",
        );
        assert!(
            !redacted.contains(super::FAKE_AWS_ACCESS_KEY),
            "redacted proxy body must not retain the raw AWS key",
        );

        // (2) Interceptor end-to-end: extraction succeeds on the redacted body
        //     and the emitted PipelineEvent never carries the raw key.
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body.clone());

        let fields = interceptor
            .intercept(&event)
            .await
            .expect("intercept must succeed")
            .expect("OpenAI body must yield extracted LlmFields");
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);

        let pipeline_event = rx.try_recv().expect("audit event must be emitted");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));
        assert!(
            !format!("{pipeline_event:?}").contains(super::FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT: emitted PipelineEvent must not contain the raw AWS key",
        );
    }

    // ── Test 2 — multi-secret security invariant on the proxy path ───────────

    /// Mirrors ST-I's multi-secret test (Test 6 in this file) for the proxy
    /// code path. Combines AWS, OpenAI, and GitHub secrets in one OpenAI
    /// request body so a single `Interceptor::intercept()` exercises the
    /// multi-finding redaction path.
    ///
    /// Asserts only the raw-secret-absence invariant — overlapping AC and
    /// entropy findings can produce garbled `[REDACTED:Kind]` labels at the
    /// boundaries (documented in `project_credential_scanner_overlap`), so
    /// asserting on specific marker shapes would be brittle. The only
    /// contract worth locking down is: no raw secret byte sequence ever
    /// reaches a PipelineEvent subscriber.
    #[tokio::test]
    async fn secret_never_leaks_into_pipeline_event_from_proxy() {
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!(
            "aws={aws} openai={openai} github={github}",
            aws = super::FAKE_AWS_ACCESS_KEY,
            openai = super::FAKE_OPENAI_KEY,
            github = super::FAKE_GITHUB_PAT,
        ));

        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body);

        let _ = interceptor.intercept(&event).await.expect("intercept must succeed");

        let pipeline_event = rx.try_recv().expect("audit event must be emitted");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));

        let event_str = format!("{pipeline_event:?}");
        for (label, raw) in [
            ("AWS access key", super::FAKE_AWS_ACCESS_KEY),
            ("OpenAI key", super::FAKE_OPENAI_KEY),
            ("GitHub PAT", super::FAKE_GITHUB_PAT),
        ] {
            assert!(
                !event_str.contains(raw),
                "SECURITY INVARIANT: emitted proxy PipelineEvent contains raw {label} — would leak to any audit subscriber",
            );
        }
    }

    // ── Test 3 — negative control on the proxy path ──────────────────────────

    /// Mirrors ST-I Test 5 (`short_high_entropy_string_does_not_trigger_scanner`)
    /// for the proxy code path. Guards against alert fatigue: short
    /// high-entropy strings that look secret-shaped but are below the
    /// `GenericHighEntropy` 20-byte floor (and lack an AC literal prefix)
    /// must produce zero findings.
    ///
    /// Two paired assertions:
    ///
    /// 1. The proxy's default scanner returns a clean `ScanResult` on the
    ///    OpenAI body shape with a 12-char alphanumeric payload.
    /// 2. `Interceptor::intercept()` still emits a `PipelineEvent::Audit`
    ///    on the broadcast channel — proving the negative path is a no-op
    ///    on redaction, not a no-op on observation.
    #[tokio::test]
    async fn short_high_entropy_string_does_not_trigger_proxy_scanner() {
        use aa_core::CredentialScanner;
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!("id={id}", id = super::SHORT_HIGH_ENTROPY));
        let body_str = std::str::from_utf8(&body).expect("body must be UTF-8 ASCII");

        // (1) Scanner-level: no findings on this short non-prefixed payload.
        let scan = CredentialScanner::new().scan(body_str);
        assert!(
            scan.is_clean(),
            "default scanner must produce zero findings on short high-entropy payload, got {:?}",
            scan.findings,
        );

        // (2) Interceptor sanity: extraction succeeds and an audit event is
        //     still emitted (negative path must not silence observation).
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body);

        let fields = interceptor
            .intercept(&event)
            .await
            .expect("intercept must succeed")
            .expect("OpenAI body must yield extracted LlmFields");
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);

        let pipeline_event = rx.try_recv().expect("audit event must be emitted on clean path");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));
    }
}
