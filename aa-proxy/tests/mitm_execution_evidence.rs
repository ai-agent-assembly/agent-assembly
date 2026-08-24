//! AAASM-5358: execution evidence on the **HTTPS MitM** paths.
//!
//! The unit tests in `proxy::tests` drive `handle_plain_http`, which is the
//! easiest path to exercise and the one that carries the least traffic. Under
//! the default `llm_only: true` every real agent request arrives as a CONNECT
//! tunnel and is handled by `handle_llm_mitm` (LLM patterns) or
//! `handle_non_llm_mitm` (operator-MitM'd hosts). Those two were previously
//! pinned by nothing: moving their audit emission back after the dial, or
//! swapping the evidence they persist, passed the whole suite.
//!
//! These tests close that. They need no mock upstream: the refusal cases never
//! dial, and the forwarding cases deliberately point `upstream_override` at a
//! bound-then-dropped port so the dial genuinely fails — which is precisely the
//! condition that distinguishes "recorded before the dial" from "recorded
//! after".

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry};
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

/// Synthetic OpenAI-style key the default scanner detects. Not a real
/// credential.
const SECRET: &str = "sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab";

/// An LLM-pattern host, so the CONNECT routes to `handle_llm_mitm`.
const LLM_HOST: &str = "api.openai.com";

/// A non-LLM host the operator has asked to MitM, so the CONNECT routes to
/// `handle_non_llm_mitm`.
const MITM_HOST: &str = "hooks.example.com";

/// The test client trusts whatever cert the proxy's MitM presents; cert
/// validity is covered elsewhere and is not what these tests are about.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// An upstream that accepts the TCP connection and then closes it, so the
/// proxy's TLS handshake fails.
///
/// Deliberately *not* a bound-then-dropped port: that leaves the address free
/// for the OS to re-hand to the proxy's own listener, which would point
/// `upstream_override` at the proxy itself and let the dial succeed — silently
/// inverting what these tests measure. Holding the listener keeps the address
/// exclusively ours, and refusing at the TLS layer makes the dial failure
/// deterministic.
async fn refusing_upstream() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    addr
}

/// A TLS upstream that completes the handshake and answers 200.
///
/// The counterpart to [`refusing_upstream`], and the one the round-2 fix was
/// missing: every call site of [`assert_one_forwarding_record`] used a failing
/// dial, so "one record per forwarded request" was only ever asserted for
/// requests where **no bytes went**. A false record emitted *after* a
/// successful dial sat outside that window entirely.
async fn live_tls_upstream() -> SocketAddr {
    // The upstream builds a rustls `ServerConfig`, which needs the process
    // crypto provider. It is called before `start_proxy`, which is the other
    // place that installs it.
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Self-signed leaf; the proxy dials with `skip_upstream_tls_verify`.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut chunk = [0u8; 8192];
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), tls.read(&mut chunk)).await;
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Drain everything the sink received and assert the request left exactly one
/// decision record, none of which claims the payload was withheld.
///
/// A forwarded request that also produced a `NotForwarded` line is B1's outcome
/// reached additively — the natural drift, and the one that actually corrupts
/// the metric, because consumers count lines rather than first-lines. Asserting
/// only on the first entry cannot see it.
async fn assert_one_forwarding_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    let first = next_entry(rx).await;
    // Give any additional emission time to land before concluding there is none.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let mut extra = Vec::new();
    while let Ok(entry) = rx.try_recv() {
        extra.push(entry);
    }
    assert!(
        extra.is_empty(),
        "a forwarded request wrote {} extra record(s): {extra:#?}",
        extra.len()
    );
    assert!(
        !first.execution.establishes_non_transmission(),
        "a forwarded request must not leave a record claiming the payload was withheld: {first:#?}"
    );
    first
}

/// Start a proxy with a live audit sink, and hand back its address plus the
/// receiving end of the sink.
async fn start_proxy(
    action: CredentialAction,
    upstream_override: Option<SocketAddr>,
    mitm_hosts: Vec<String>,
    ca_dir: &std::path::Path,
) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
    install_crypto();
    let ca = CaStore::load_or_create(ca_dir).await.unwrap();

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts,
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: action,
        upstream_override,
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        // The mock/dead upstreams are on loopback, which the SSRF guard would
        // (correctly) refuse in production.
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
    };

    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let (audit_tx, audit_rx) = mpsc::channel(16);
    let server = aa_proxy::proxy::ProxyServer::new_with_audit_sink(config, ca, event_tx, Some(audit_tx));
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    (addr, audit_rx)
}

/// Open a CONNECT tunnel, complete the MitM TLS handshake, send `request`, and
/// return whatever the client saw.
async fn mitm_roundtrip(proxy: SocketAddr, host: &str, request: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("200"), "tunnel not established: {line}");
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await.unwrap();
        if header.trim().is_empty() {
            break;
        }
    }

    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(host.to_string()).unwrap();
    let mut tls = connector.connect(server_name, reader.into_inner()).await.unwrap();

    tls.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// A body whose redaction re-inspects clean.
fn scrubbable_body() -> String {
    format!("leaking {SECRET} here")
}

fn post(host: &str, body: &str) -> String {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    )
}

/// Wait briefly for the record: the handler runs in a spawned connection task,
/// so `try_recv` immediately after the client read can race it.
async fn next_entry(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the decision record")
        .expect("the audit sink closed without producing a record")
}

// ── handle_llm_mitm — the path that carries real agent traffic ──────────────

#[tokio::test]
async fn llm_mitm_refusal_persists_non_transmission_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, None, Vec::new(), dir.path()).await;

    let response = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;
    assert!(
        response.contains("403"),
        "the request must be refused, got: {response:?}"
    );

    let entry = next_entry(&mut audit).await;
    // Non-vacuity first: the record has content, so the assertions below are
    // being made about something.
    assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
    assert_eq!(entry.host, LLM_HOST);
    assert!(
        !entry.credential_findings.is_empty(),
        "a blocked credential body must carry its findings"
    );

    assert!(
        entry.execution.establishes_non_transmission(),
        "a pre-transmission refusal is the only shape that may support a prevention claim, got {:?}",
        entry.execution
    );
    assert_eq!(entry.execution.transmission.as_str(), "not_forwarded");
    assert!(
        entry.probe_correlation.is_none(),
        "ordinary traffic must not look synthetic"
    );

    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(
        !serialized.contains(SECRET),
        "SECURITY INVARIANT VIOLATED: raw value in the persisted record: {serialized}"
    );
}

#[tokio::test]
async fn llm_mitm_redaction_records_a_transmission_not_a_prevention() {
    let dir = tempfile::tempdir().unwrap();
    let dead = refusing_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.transmission.as_str(), "forwarded_clean");
    assert!(entry.execution.transmission.proves_transmission());
    assert!(
        !entry.execution.establishes_non_transmission(),
        "a successful redaction is a transformed transmission, not a prevented one"
    );
}

/// The ordering claim on the path that matters. The upstream is a dead port, so
/// the dial fails — the record must already exist. Moving the emission back
/// after `dial_upstream_tls` makes this the only test that notices.
#[tokio::test]
async fn llm_mitm_records_the_forward_before_the_dial_that_fails() {
    let dir = tempfile::tempdir().unwrap();
    let dead = refusing_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
    assert!(
        entry.execution.transmission.proves_transmission(),
        "the observation that unlocked the dial must say the bytes went"
    );
}

/// `alert_only` on the LLM path: detected, forwarded unchanged, and recorded as
/// a dry-run transmission that can never be counted as prevention.
#[tokio::test]
async fn llm_mitm_alert_only_records_an_observed_transmission() {
    let dir = tempfile::tempdir().unwrap();
    let dead = refusing_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::AlertOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Forwarded);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.mode, aa_core::policy::EnforcementMode::Observe);
    assert!(!entry.execution.establishes_non_transmission());
    // The unmodified body carried the value, and the proxy says so.
    assert_eq!(
        entry.execution.transmission.as_str(),
        "forwarded_carrying_sensitive_value"
    );
}

/// A protection probe's own refusal is real, but synthetic. Without the
/// correlation marker every probe run under `block` would contribute a
/// prevented transmission indistinguishable from a real one.
#[tokio::test]
async fn a_probe_refusal_is_marked_as_synthetic_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, None, Vec::new(), dir.path()).await;

    let body = scrubbable_body();
    let correlation = "0123456789abcdef0123456789abcdef";
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOST}\r\n\
         x-agent-assembly-probe: {correlation}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = mitm_roundtrip(proxy, LLM_HOST, &request).await;

    let entry = next_entry(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(
        entry.probe_correlation.as_deref(),
        Some(correlation),
        "a probe's record must be identifiable as synthetic"
    );
    // A real block during a probe is genuinely a refusal, so the evidence is
    // not weakened — the marker is what lets a consumer exclude it.
    assert!(entry.execution.establishes_non_transmission());
}

/// The other probe branches: withheld by the probe protocol, not by policy, so
/// they claim nothing in either direction.
#[tokio::test]
async fn a_probe_under_redact_only_claims_no_prevention() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, None, Vec::new(), dir.path()).await;

    let body = scrubbable_body();
    let correlation = "abcdef0123456789abcdef0123456789";
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOST}\r\n\
         x-agent-assembly-probe: {correlation}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = mitm_roundtrip(proxy, LLM_HOST, &request).await;

    let entry = next_entry(&mut audit).await;
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(
        entry.execution.transmission.as_str(),
        "not_recorded",
        "the probe protocol withheld these bytes, not the policy"
    );
    assert!(
        !entry.execution.establishes_non_transmission(),
        "a probe under redact_only must not manufacture a prevented transmission"
    );
    assert_eq!(entry.probe_correlation.as_deref(), Some(correlation));

    // AAASM-5449: this branch used to record `ForwardedRedacted` for a request
    // that was never dialled — the verdict's counterfactual, sitting beside
    // the true `execution`. The decision now says what happened.
    assert_eq!(
        entry.decision,
        ProxyAuditDecision::AnsweredLocally,
        "a request the proxy answered itself is not a forward: {entry:#?}"
    );
}

/// The counterfactual under `alert_only`, which is the other branch that used
/// to claim a forward. Pinned separately from the `redact_only` case so the
/// two cannot drift, and paired with the record's own evidence so the
/// assertion is about a *consistent* record rather than one field.
#[tokio::test]
async fn a_probe_the_proxy_answered_is_never_recorded_as_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::AlertOnly, None, Vec::new(), dir.path()).await;

    let body = scrubbable_body();
    let correlation = "fedcba9876543210fedcba9876543210";
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOST}\r\n\
         x-agent-assembly-probe: {correlation}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let response = mitm_roundtrip(proxy, LLM_HOST, &request).await;
    // Non-vacuity: the probe really was adjudicated and answered here — the
    // proxy replied rather than relaying, and the scanner really did find the
    // synthetic credential.
    assert!(
        !response.is_empty(),
        "the probe must have been answered by the proxy: {response:?}"
    );

    let entry = next_entry(&mut audit).await;
    assert_eq!(entry.probe_correlation.as_deref(), Some(correlation));
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.decision, ProxyAuditDecision::AnsweredLocally);
    assert!(
        !matches!(
            entry.decision,
            ProxyAuditDecision::Forwarded | ProxyAuditDecision::ForwardedRedacted
        ),
        "no bytes were relayed, so no forwarded variant may appear: {entry:#?}"
    );
    // And the decision agrees with the evidence rather than contradicting it.
    assert!(
        !entry.execution.transmission.proves_transmission(),
        "the record claims a transmission it also says never happened: {entry:#?}"
    );
    assert!(!entry.execution.establishes_non_transmission());
}

// ── handle_non_llm_mitm — operator-MitM'd hosts ────────────────────────────

#[tokio::test]
async fn non_llm_mitm_refusal_persists_non_transmission_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, None, vec![MITM_HOST.to_string()], dir.path()).await;

    let response = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;
    assert!(
        response.contains("403"),
        "the request must be refused, got: {response:?}"
    );

    let entry = next_entry(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
    assert_eq!(entry.host, MITM_HOST);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert!(entry.execution.establishes_non_transmission());
    assert_eq!(entry.execution.transmission.as_str(), "not_forwarded");

    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(
        !serialized.contains(SECRET),
        "SECURITY INVARIANT VIOLATED: raw value in the persisted record: {serialized}"
    );
}

/// The ordering claim on the non-LLM MitM path.
#[tokio::test]
async fn non_llm_mitm_records_the_forward_before_the_dial_that_fails() {
    let dir = tempfile::tempdir().unwrap();
    let dead = refusing_upstream().await;
    let (proxy, mut audit) = start_proxy(
        CredentialAction::RedactOnly,
        Some(dead),
        vec![MITM_HOST.to_string()],
        dir.path(),
    )
    .await;

    let _ = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.transmission.as_str(), "forwarded_clean");
    assert!(!entry.execution.establishes_non_transmission());
}

/// `alert_only` on the non-LLM MitM path, which is the other place the
/// detected-but-forwarded numerator comes from.
#[tokio::test]
async fn non_llm_mitm_alert_only_records_an_observed_transmission() {
    let dir = tempfile::tempdir().unwrap();
    let dead = refusing_upstream().await;
    let (proxy, mut audit) = start_proxy(
        CredentialAction::AlertOnly,
        Some(dead),
        vec![MITM_HOST.to_string()],
        dir.path(),
    )
    .await;

    let _ = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Forwarded);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.mode, aa_core::policy::EnforcementMode::Observe);
    assert!(!entry.execution.establishes_non_transmission());
}

// ── the probe marker on the handlers that do not adjudicate ────────────────

/// `handle_non_llm_mitm` never speaks the probe protocol, but it can still
/// *receive* a probe — and under `block` it refuses it before any dial,
/// producing a record that satisfies every ADR 0032 §8 condition. Unmarked,
/// that is a synthetic prevention indistinguishable from a real one.
#[tokio::test]
async fn a_probe_refused_by_the_non_llm_handler_is_marked_synthetic() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, None, vec![MITM_HOST.to_string()], dir.path()).await;

    let body = scrubbable_body();
    let correlation = "0123456789abcdef0123456789abcdef";
    let request = format!(
        "POST /ingest HTTP/1.1\r\nHost: {MITM_HOST}\r\n\
         x-agent-assembly-probe: {correlation}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = mitm_roundtrip(proxy, MITM_HOST, &request).await;

    let entry = next_entry(&mut audit).await;
    // Non-vacuity: this really is the refusal branch, with content.
    assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert!(
        entry.execution.establishes_non_transmission(),
        "the refusal is genuine — the marker is what makes it excludable"
    );
    assert_eq!(
        entry.probe_correlation.as_deref(),
        Some(correlation),
        "a probe refused by the non-LLM handler must still be identifiable as synthetic"
    );
}

/// The same gap on the plain-HTTP path.
#[tokio::test]
async fn a_probe_refused_by_the_plain_http_handler_is_marked_synthetic() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, None, Vec::new(), dir.path()).await;

    let body = scrubbable_body();
    let correlation = "abcdef0123456789abcdef0123456789";
    let request = format!(
        "POST http://plain.example.com/ingest HTTP/1.1\r\nHost: plain.example.com\r\n\
         x-agent-assembly-probe: {correlation}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), client.read_to_end(&mut out)).await;
    assert!(
        String::from_utf8_lossy(&out).contains("403"),
        "the probe body must be refused: {:?}",
        String::from_utf8_lossy(&out)
    );

    let entry = next_entry(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Blocked);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.probe_correlation.as_deref(), Some(correlation));
}

// ── the transparent tunnel, the third route to the wire ────────────────────

/// Under the default `llm_only: true` this path carries every non-LLM
/// connection, and it was the route S6 found ungated. It inspects nothing, so
/// the honest outcome is that it writes **no** decision event — inventing one
/// would change what the audit trail counts. Pinned here because nothing
/// persisted means no other test can catch a regression in it.
#[tokio::test]
async fn the_transparent_tunnel_relays_and_records_no_decision_event() {
    // A plain TCP echo-ish upstream: the tunnel is a raw byte relay, so no TLS.
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = upstream.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        // No assertion here: this task's handle is never awaited, so a failure
        // inside it could not fail the test. The `pong` round-trip below is
        // what proves the relay worked.
        let _ = sock.read(&mut buf).await;
        let _ = sock.write_all(b"pong").await;
        let _ = sock.shutdown().await;
    });

    let dir = tempfile::tempdir().unwrap();
    // `llm_only: true` with no `mitm_hosts` entry ⇒ a non-LLM CONNECT is
    // transparently tunnelled rather than MitM'd.
    let (proxy, mut audit) = start_proxy(CredentialAction::Block, Some(upstream_addr), Vec::new(), dir.path()).await;

    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(b"CONNECT plain.example.com:443 HTTP/1.1\r\nHost: plain.example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("200"), "tunnel not established: {line}");
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await.unwrap();
        if header.trim().is_empty() {
            break;
        }
    }
    // Raw bytes through the tunnel — no TLS, no inspection.
    let mut stream = reader.into_inner();
    stream.write_all(b"ping").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read_to_end(&mut out)).await;
    assert_eq!(&out, b"pong", "the tunnel must relay the upstream response");

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        audit.try_recv().is_err(),
        "the transparent tunnel took no decision, so it must invent no decision event"
    );
}

/// The case the round-2 fix could not reach: a **successful** MitM forward with
/// a live sink, counted.
///
/// Every other `assert_one_forwarding_record` call site uses
/// [`refusing_upstream`], so the one-record property was only ever asserted
/// where the dial failed — leaving a false record emitted *after*
/// `dial_upstream_tls` outside the assertion window. Nothing in the repo drove
/// a successful MitM forward with an audit sink attached.
#[tokio::test]
async fn a_successful_llm_mitm_forward_writes_exactly_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = live_tls_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, Some(upstream), Vec::new(), dir.path()).await;

    let response = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;
    // Non-vacuity: the bytes genuinely went and the upstream genuinely answered.
    assert!(
        response.contains("200 OK"),
        "the request must have reached a live upstream, got: {response:?}"
    );

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::ForwardedRedacted);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert!(entry.execution.transmission.proves_transmission());
}

/// The same, on the non-LLM MitM handler.
#[tokio::test]
async fn a_successful_non_llm_mitm_forward_writes_exactly_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = live_tls_upstream().await;
    let (proxy, mut audit) = start_proxy(
        CredentialAction::AlertOnly,
        Some(upstream),
        vec![MITM_HOST.to_string()],
        dir.path(),
    )
    .await;

    let response = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;
    assert!(
        response.contains("200 OK"),
        "the request must have reached a live upstream, got: {response:?}"
    );

    let entry = assert_one_forwarding_record(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Forwarded);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.mode, aa_core::policy::EnforcementMode::Observe);
}
