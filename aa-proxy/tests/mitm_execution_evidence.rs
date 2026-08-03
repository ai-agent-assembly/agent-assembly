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
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::TlsConnector;

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

/// An address nothing is listening on: bound to claim it, then dropped.
async fn dead_upstream() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
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
        // The mock/dead upstreams are on loopback, which the SSRF guard would
        // (correctly) refuse in production.
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
    let dead = dead_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = next_entry(&mut audit).await;
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
    let dead = dead_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::RedactOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = next_entry(&mut audit).await;
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
    let dead = dead_upstream().await;
    let (proxy, mut audit) = start_proxy(CredentialAction::AlertOnly, Some(dead), Vec::new(), dir.path()).await;

    let _ = mitm_roundtrip(proxy, LLM_HOST, &post(LLM_HOST, &scrubbable_body())).await;

    let entry = next_entry(&mut audit).await;
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
    let dead = dead_upstream().await;
    let (proxy, mut audit) = start_proxy(
        CredentialAction::RedactOnly,
        Some(dead),
        vec![MITM_HOST.to_string()],
        dir.path(),
    )
    .await;

    let _ = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;

    let entry = next_entry(&mut audit).await;
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
    let dead = dead_upstream().await;
    let (proxy, mut audit) = start_proxy(
        CredentialAction::AlertOnly,
        Some(dead),
        vec![MITM_HOST.to_string()],
        dir.path(),
    )
    .await;

    let _ = mitm_roundtrip(proxy, MITM_HOST, &post(MITM_HOST, &scrubbable_body())).await;

    let entry = next_entry(&mut audit).await;
    assert_eq!(entry.decision, ProxyAuditDecision::Forwarded);
    assert!(!entry.credential_findings.is_empty(), "otherwise this asserts nothing");
    assert_eq!(entry.execution.mode, aa_core::policy::EnforcementMode::Observe);
    assert!(!entry.execution.establishes_non_transmission());
}
