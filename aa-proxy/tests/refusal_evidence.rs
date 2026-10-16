//! AAASM-5449: the proxy's *rule* refusals as persisted evidence.
//!
//! AAASM-5358 persisted the credential verdict's refusal. The refusals that are
//! harder to argue with — the egress denylist, the network allowlist, an
//! in-tunnel forged `Host`, a cleartext downgrade to an LLM host, and a gateway
//! `tools/call` deny — were logged and discarded, so ADR 0032 §8 could see
//! redaction-with-forwarding but not the cases where the request was refused
//! outright before any dial.
//!
//! Every test here has to survive two mutations, and the fixtures are built for
//! the second one:
//!
//! * severing the persistence at one call site must kill this file's test for
//!   **that** refusal kind and no other — otherwise the suite proves only that
//!   *something* persists, not that each control does;
//! * swapping the evidence for a forwarded variant must kill the assertion.
//!   A count assertion handed nothing but refusals cannot see that, so the
//!   refusal assertions are paired with a live forward through the *same*
//!   proxy — see [`a_refusal_and_a_forward_are_distinguishable_on_one_proxy`].

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry, RefusalRule};
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

/// An LLM-pattern host, so a CONNECT to it routes to `handle_llm_mitm`.
const LLM_HOST: &str = "api.openai.com";

/// A non-LLM host the operator asked to MitM, so a CONNECT routes to
/// `handle_non_llm_mitm`.
const MITM_HOST: &str = "hooks.example.com";

/// A host the operator put on the denylist.
const DENIED_HOST: &str = "evil.example.com";

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

/// Everything a fixture varies about the proxy under test.
#[derive(Default)]
struct Fixture {
    denied_hosts: Vec<String>,
    network_allowlist: Vec<String>,
    mitm_hosts: Vec<String>,
    upstream_override: Option<SocketAddr>,
    gateway_endpoint: Option<String>,
    /// Turn the SSRF guard back on. Every other fixture dials a loopback mock,
    /// which the guard would (correctly) refuse.
    block_private_targets: bool,
    /// AAASM-5855: the value read from this proxy process's own `AA_AGENT_ID`
    /// env var (`ProxyConfig::agent_id`). `None` reproduces the pre-fix default.
    agent_id: Option<String>,
    /// AAASM-6353: override the scanner's action. `None` keeps the permissive
    /// `AlertOnly` every refusal test above relies on.
    credential_action: Option<CredentialAction>,
    /// AAASM-6355: `ProxyConfig::mcp_fail_open`.
    mcp_fail_open: bool,
}

/// Start a proxy with a live audit sink; hand back its address and the sink's
/// receiving end.
async fn start_proxy(fixture: Fixture, ca_dir: &std::path::Path) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
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
        mitm_hosts: fixture.mitm_hosts,
        denied_hosts: fixture.denied_hosts,
        network_allowlist: fixture.network_allowlist,
        skip_upstream_tls_verify: true,
        // Every refusal under test here fires before the credential scanner has
        // any say, so the scanner is left in its most permissive mode: a record
        // that appears anyway cannot have come from the credential verdict.
        credential_action: fixture.credential_action.unwrap_or(CredentialAction::AlertOnly),
        upstream_override: fixture.upstream_override,
        gateway_endpoint: fixture.gateway_endpoint,
        mcp_fail_open: fixture.mcp_fail_open,
        network_fail_open: false,
        agent_id: fixture.agent_id,
        ready_file: None,
        parent_pid: None,
        // The mock upstreams are on loopback, which the SSRF guard would
        // (correctly) refuse in production.
        allow_private_connect_targets: !fixture.block_private_targets,
        trusted_config_path: None,
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

/// A TLS upstream that completes the handshake and answers 200 — the live
/// forward that keeps the refusal assertions from being vacuous.
async fn live_tls_upstream() -> SocketAddr {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

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

/// A TLS upstream that answers with a `Transfer-Encoding: chunked` body
/// (AAASM-5645) instead of a `Content-Length` one — the framing
/// `read_http_response` used to leave empty. The marker is split across a
/// chunk boundary so a decoder that only reads the first chunk, or
/// mis-consumes the inter-chunk CRLF, fails to reproduce it whole.
async fn chunked_tls_upstream() -> SocketAddr {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

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
                // "chunk-boundary-marker" split as "chunk-boundary-" (15) + "marker" (6).
                let body = b"HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Transfer-Encoding: chunked\r\n\
                             Connection: close\r\n\
                             \r\n\
                             f\r\nchunk-boundary-\r\n\
                             6\r\nmarker\r\n\
                             0\r\n\r\n";
                let _ = tls.write_all(body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// AAASM-6353: a TLS upstream that records the request bytes it receives, so a
/// test can assert on what actually reached the wire (or that nothing did).
async fn recording_tls_upstream() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let sink = received.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let sink = sink.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read until the peer closes or goes idle, so a request split
                // across TLS records is recorded whole.
                let mut chunk = [0u8; 8192];
                while let Ok(Ok(n)) =
                    tokio::time::timeout(std::time::Duration::from_millis(300), tls.read(&mut chunk)).await
                {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&chunk[..n]);
                    if sink.lock().unwrap().windows(4).any(|w| w == b"\r\n\r\n") && n < chunk.len() {
                        break;
                    }
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, received)
}

/// Open a CONNECT tunnel and return the proxy's answer to the CONNECT itself.
///
/// `Err(response)` when the proxy refused the tunnel — which is the case every
/// CONNECT-time refusal test is about.
async fn open_tunnel(proxy: SocketAddr, host: &str) -> Result<BufReader<TcpStream>, String> {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    if !line.contains("200") {
        return Err(line);
    }
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await.unwrap();
        if header.trim().is_empty() {
            break;
        }
    }
    Ok(reader)
}

/// Complete the MitM TLS handshake on an open tunnel, send `request`, and
/// return whatever the client saw.
async fn mitm_send(reader: BufReader<TcpStream>, host: &str, request: &str) -> String {
    mitm_send_bytes(reader, host, request.as_bytes()).await
}

async fn mitm_send_bytes(reader: BufReader<TcpStream>, host: &str, request: &[u8]) -> String {
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(host.to_string()).unwrap();
    let mut tls = connector.connect(server_name, reader.into_inner()).await.unwrap();

    tls.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Send one plain (non-CONNECT) HTTP request and return the client's view.
async fn plain_send(proxy: SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), client.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Wait briefly for a record: the handler runs in a spawned connection task, so
/// `try_recv` immediately after the client read can race it.
async fn next_entry(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
        .await
        .expect("timed out waiting for the decision record")
        .expect("the audit sink closed without producing a record")
}

/// Assert this refusal left exactly one record, that the record is the shape
/// ADR 0032 §8 may count, and that it names `rule`.
///
/// `rule` is what makes the falsification per-kind: severing one call site has
/// to kill one test, not merely reduce a total that another site still tops up.
async fn sole_refusal_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>, rule: RefusalRule) -> ProxyAuditEntry {
    let first = next_entry(rx).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let mut extra = Vec::new();
    while let Ok(entry) = rx.try_recv() {
        extra.push(entry);
    }
    assert!(
        extra.is_empty(),
        "a refused request wrote {} extra record(s): {extra:#?}",
        extra.len()
    );
    assert_eq!(
        first.decision,
        ProxyAuditDecision::Blocked,
        "a refusal must not be recorded as a forward: {first:#?}"
    );
    assert_eq!(
        first.execution.transmission.as_str(),
        "not_forwarded",
        "the bytes never left, and only that observation can support a prevention claim: {first:#?}"
    );
    assert!(
        first.execution.establishes_non_transmission(),
        "the record fails ADR 0032 §8's conditions and cannot be counted: {first:#?}"
    );
    assert!(
        first.credential_findings.is_empty(),
        "a rule refusal fires before the credential verdict exists: {first:#?}"
    );
    assert_eq!(
        first.refusal_rule,
        Some(rule),
        "the record must name the control that refused: {first:#?}"
    );
    // ADR 0032 §9: this sink is not the tamper-evident tier, so no byte offset
    // may reach it. A refusal carries no findings, but the line is checked
    // anyway — the guarantee is about the tier, not about which branch wrote
    // the record.
    let serialized = serde_json::to_string(&first).unwrap();
    assert!(
        !serialized.contains("\"offset\""),
        "a byte offset reached the untrusted tier: {serialized}"
    );
    first
}

/// The MCP `tools/call` envelope the gateway stub denies.
fn mcp_tools_call_body() -> String {
    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything","arguments":{"path":"/"}}}"#
        .to_owned()
}

fn post(host: &str, path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    )
}

// ── CONNECT-time egress policy ─────────────────────────────────────────────

#[tokio::test]
async fn a_connect_denylist_refusal_persists_non_transmission_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    // Non-vacuity: the tunnel really was refused, so a record that turns up is
    // a record about a refusal.
    let refused = open_tunnel(proxy, DENIED_HOST).await;
    assert!(
        refused.is_err(),
        "the denylisted CONNECT must be refused, not tunnelled"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(entry.host, DENIED_HOST);
    assert!(
        entry.probe_correlation.is_none(),
        "ordinary traffic must not look synthetic"
    );
    // AAASM-5855: this is the negative control for
    // `a_refusal_is_persisted_with_the_configured_agent_id` below — this
    // fixture's `agent_id` is `Fixture::default()`'s `None`, so the persisted
    // record must say so explicitly. Without this assertion the sibling test
    // cannot prove anything: `agent_id: self.agent_id.or(Some("x".into()))`
    // would pass every test in this file undetected.
    assert_eq!(
        entry.agent_id, None,
        "an unset agent_id must not be defaulted to a value"
    );
}

/// AAASM-5855: reproduction and regression for the `agent_id="<unknown>"`
/// audit-attribution gap. Before the fix, `DecisionRecord::send` hardcoded
/// `agent_id: None` regardless of what the proxy was configured with — this
/// asserts the persisted record carries the real configured identity instead.
///
/// The negative control is the sibling test right above: it runs the same
/// refusal through a proxy configured with `agent_id: None` (the `Fixture`
/// default) and would have caught a regression that made `agent_id` `Some`
/// unconditionally.
#[tokio::test]
async fn a_refusal_is_persisted_with_the_configured_agent_id() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            agent_id: Some("did:key:z6MkAAASM5855".to_string()),
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let refused = open_tunnel(proxy, DENIED_HOST).await;
    assert!(
        refused.is_err(),
        "the denylisted CONNECT must be refused, not tunnelled"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(
        entry.agent_id,
        Some("did:key:z6MkAAASM5855".to_string()),
        "the persisted record must carry the registered agent's identity, not <unknown>: {entry:#?}"
    );
}

#[tokio::test]
async fn a_connect_network_allowlist_refusal_persists_non_transmission_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            // A non-empty allowlist that this host does not match.
            network_allowlist: vec![LLM_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let refused = open_tunnel(proxy, "unlisted.example.com").await;
    assert!(refused.is_err(), "a host outside the allowlist must be refused");

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressAllowlist).await;
    assert_eq!(entry.host, "unlisted.example.com");
}

/// The SSRF guard is an egress refusal too, and it fires ahead of both the
/// denylist and the allowlist — so it needs its own rule token or a
/// metadata-endpoint refusal would be attributed to operator policy.
#[tokio::test]
async fn a_connect_to_a_blocked_address_range_persists_an_ssrf_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            block_private_targets: true,
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let refused = open_tunnel(proxy, "169.254.169.254").await;
    assert!(refused.is_err(), "the cloud metadata endpoint must be refused");

    let entry = sole_refusal_record(&mut audit, RefusalRule::SsrfBlockedAddress).await;
    assert_eq!(entry.host, "169.254.169.254");
}

/// A probe whose CONNECT is refused is a real refusal of synthetic traffic.
/// The CONNECT head is drained and discarded, so before AAASM-5449 read the
/// correlation id out of it this record would have been an unmarked prevention
/// — one per probe run against a denied host, indistinguishable from a real
/// leak that was stopped.
#[tokio::test]
async fn a_probe_whose_connect_is_refused_is_marked_synthetic() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let correlation = "0123456789abcdef0123456789abcdef";
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(
            format!(
                "CONNECT {DENIED_HOST}:443 HTTP/1.1\r\nHost: {DENIED_HOST}:443\r\n\
                 x-agent-assembly-probe: {correlation}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.contains("403"), "the denylisted CONNECT must be refused: {line}");

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(
        entry.probe_correlation.as_deref(),
        Some(correlation),
        "a probe's own refusal must be excludable from a prevention rate"
    );
    // The refusal is genuine — the marker is what makes it excludable, not
    // what weakens it.
    assert!(entry.execution.establishes_non_transmission());
}

// ── in-tunnel host forgery, on both MitM handlers ──────────────────────────

#[tokio::test]
async fn an_in_tunnel_forged_host_on_the_llm_path_persists_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    // CONNECT to an allowed LLM host, then forge the in-tunnel `Host`.
    let tunnel = open_tunnel(proxy, LLM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, LLM_HOST, &post(DENIED_HOST, "/v1/chat/completions", "hello")).await;
    assert!(
        response.contains("403"),
        "the forged in-tunnel host must be refused, got: {response:?}"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(
        entry.host, DENIED_HOST,
        "the record must name the host that was refused, not the one the tunnel was opened to"
    );
}

#[tokio::test]
async fn an_in_tunnel_forged_host_on_the_non_llm_path_persists_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            mitm_hosts: vec![MITM_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, MITM_HOST, &post(DENIED_HOST, "/ingest", "hello")).await;
    assert!(
        response.contains("403"),
        "the forged in-tunnel host must be refused, got: {response:?}"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(entry.host, DENIED_HOST);
}

// ── plain HTTP ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_plain_http_egress_refusal_persists_non_transmission_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let response = plain_send(
        proxy,
        &format!("POST http://{DENIED_HOST}/ingest HTTP/1.1\r\nHost: {DENIED_HOST}\r\nContent-Length: 5\r\n\r\nhello"),
    )
    .await;
    assert!(response.contains("403"), "the denylisted host must be refused");

    let entry = sole_refusal_record(&mut audit, RefusalRule::EgressDenylist).await;
    assert_eq!(entry.host, DENIED_HOST);
}

#[tokio::test]
async fn a_plaintext_downgrade_to_an_llm_host_persists_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let (proxy, mut audit) = start_proxy(Fixture::default(), dir.path()).await;

    let response = plain_send(
        proxy,
        &format!(
            "POST http://{LLM_HOST}/v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOST}\r\nContent-Length: 5\r\n\r\nhello"
        ),
    )
    .await;
    assert!(
        response.contains("403"),
        "cleartext to an LLM host bypasses DLP and must be refused"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::PlaintextLlmDowngrade).await;
    assert_eq!(entry.host, LLM_HOST);
}

// ── MCP tools/call deny ────────────────────────────────────────────────────

#[tokio::test]
async fn an_mcp_tools_call_deny_persists_a_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_denying_gateway().await;
    let (proxy, mut audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(gateway),
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_tools_call_body())).await;
    // Non-vacuity: the gateway stub really denied, and the client got the
    // JSON-RPC error envelope rather than an upstream response.
    assert!(
        response.contains("no tools for you"),
        "the gateway's deny reason must reach the client, got: {response:?}"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::McpToolCall).await;
    assert_eq!(entry.host, MITM_HOST);
}

// ── Gateway-backed network-egress deny (AAASM-5851) ────────────────────────

/// The CONNECT-time and in-tunnel gateway checks are two independent
/// decisions against two different hosts, not one check reused for both.
/// `AllowOnlyNetworkHost` allows only `MITM_HOST`, so the CONNECT (whose
/// `NetworkCallContext.host` is `MITM_HOST`) succeeds, opening the tunnel —
/// then a forged in-tunnel `Host:` header naming a *different* host is
/// re-evaluated against the same gateway and denied, proving
/// `in_tunnel_deny_reason`'s AAASM-4829 defense is gateway-bound in managed
/// mode, not just the local allowlist a no-gateway fixture would use.
#[tokio::test]
async fn a_forged_in_tunnel_host_is_denied_by_gateway_policy() {
    const FORGED_HOST: &str = "evil.attacker.example";

    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_network_allow_one_host_gateway(MITM_HOST).await;
    let (proxy, mut audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(gateway),
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    // CONNECT to the one host the gateway allows — the tunnel opens.
    let tunnel = open_tunnel(proxy, MITM_HOST)
        .await
        .expect("CONNECT to the gateway-allowed host must succeed");

    // Inside that tunnel, forge a Host header naming a host the gateway
    // never allowed. The SNI/tunnel host is still MITM_HOST (AcceptAnyCert
    // skips certificate-name verification), so this exercises the in-tunnel
    // Host-header re-check specifically, not the CONNECT-time check again.
    let request = format!("GET /v1/x HTTP/1.1\r\nHost: {FORGED_HOST}\r\nContent-Length: 0\r\n\r\n");
    let response = mitm_send(tunnel, MITM_HOST, &request).await;
    assert!(
        response.contains("403"),
        "a forged in-tunnel Host naming a gateway-denied host must be refused, got: {response:?}"
    );

    let entry = sole_refusal_record(&mut audit, RefusalRule::GatewayEgressPolicy).await;
    assert_eq!(
        entry.host, FORGED_HOST,
        "the persisted refusal must name the forged host, not the CONNECT host"
    );
}

/// A minimal `PolicyService` that denies every `CheckAction`.
mod gateway_stub {
    use std::pin::Pin;

    use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
    use aa_proto::assembly::policy::v1::{
        BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
        OpControlSubscribeRequest,
    };
    use tokio::net::TcpListener;
    use tonic::codegen::tokio_stream::Stream;
    use tonic::{Request, Response, Status};

    pub const DENY_REASON: &str = "no tools for you";

    /// Denies MCP `tools/call` (`ActionContext::ToolCall`), allows everything
    /// else. AAASM-5851: the proxy now also sends a `NetworkCall` context for
    /// every CONNECT/in-tunnel/plain-HTTP destination when a gateway is
    /// configured, so a stub that denied unconditionally would refuse the
    /// CONNECT this test needs to succeed *before* it can reach the MCP
    /// tools/call this test actually exercises. Branching on the action type
    /// keeps this test's original, still-valid intent: prove an MCP deny
    /// specifically persists a refusal record.
    #[derive(Default)]
    struct DenyEverything;

    #[tonic::async_trait]
    impl PolicyService for DenyEverything {
        async fn check_action(
            &self,
            req: Request<CheckActionRequest>,
        ) -> Result<Response<CheckActionResponse>, Status> {
            use aa_proto::assembly::policy::v1::action_context::Action;
            let is_tool_call = matches!(
                req.get_ref().context.as_ref().and_then(|c| c.action.as_ref()),
                Some(Action::ToolCall(_))
            );
            let decision = if is_tool_call {
                aa_proto::assembly::common::v1::Decision::Deny
            } else {
                aa_proto::assembly::common::v1::Decision::Allow
            };
            Ok(Response::new(CheckActionResponse {
                decision: decision as i32,
                reason: if is_tool_call {
                    DENY_REASON.to_owned()
                } else {
                    String::new()
                },
                ..Default::default()
            }))
        }

        // The proxy calls `check_action` and nothing else; the remaining RPCs
        // exist only to satisfy the generated trait.
        async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }

        type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

        async fn op_control_stream(
            &self,
            _req: Request<OpControlSubscribeRequest>,
        ) -> Result<Response<Self::OpControlStreamStream>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    /// Bind a gRPC server on an ephemeral port and return its `http://` endpoint.
    ///
    /// The port is claimed by binding and releasing, the same way the proxy
    /// fixture picks its own address; `ProxyServer::run` fails closed if the
    /// gateway is not up, so the sleep below is load-bearing rather than
    /// decorative.
    pub async fn spawn_denying_gateway() -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(DenyEverything))
                .serve(addr)
                .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        format!("http://{addr}")
    }

    /// AAASM-5851: allows a `NetworkCall` only when its host matches
    /// `allowed_host` exactly; denies every other host and every non-network
    /// action. Lets a test prove the CONNECT-time and in-tunnel gateway
    /// checks are two independent decisions against two different hosts —
    /// `DenyEverything` above can't do that, since it doesn't look at the
    /// request at all for non-`ToolCall` actions.
    struct AllowOnlyNetworkHost {
        allowed_host: String,
    }

    #[tonic::async_trait]
    impl PolicyService for AllowOnlyNetworkHost {
        async fn check_action(
            &self,
            req: Request<CheckActionRequest>,
        ) -> Result<Response<CheckActionResponse>, Status> {
            use aa_proto::assembly::policy::v1::action_context::Action;
            let host = match req.get_ref().context.as_ref().and_then(|c| c.action.as_ref()) {
                Some(Action::NetworkCall(nc)) => Some(nc.host.clone()),
                _ => None,
            };
            let allow = host.as_deref() == Some(self.allowed_host.as_str());
            Ok(Response::new(CheckActionResponse {
                decision: if allow {
                    aa_proto::assembly::common::v1::Decision::Allow as i32
                } else {
                    aa_proto::assembly::common::v1::Decision::Deny as i32
                },
                reason: if allow {
                    String::new()
                } else {
                    format!("host {host:?} is not the one policy allows")
                },
                ..Default::default()
            }))
        }

        async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }

        type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

        async fn op_control_stream(
            &self,
            _req: Request<OpControlSubscribeRequest>,
        ) -> Result<Response<Self::OpControlStreamStream>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    /// Bind a gateway that allows `NetworkCall` egress to `allowed_host` only.
    pub async fn spawn_network_allow_one_host_gateway(allowed_host: &str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let service = AllowOnlyNetworkHost {
            allowed_host: allowed_host.to_string(),
        };
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(service))
                .serve(addr)
                .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        format!("http://{addr}")
    }

    /// AAASM-6353: allows `NetworkCall`, answers `Redact` to every MCP
    /// `tools/call` — the gateway finding the proxy's scanner may not share.
    #[derive(Default)]
    struct RedactToolCalls;

    #[tonic::async_trait]
    impl PolicyService for RedactToolCalls {
        async fn check_action(
            &self,
            req: Request<CheckActionRequest>,
        ) -> Result<Response<CheckActionResponse>, Status> {
            use aa_proto::assembly::policy::v1::action_context::Action;
            let is_tool_call = matches!(
                req.get_ref().context.as_ref().and_then(|c| c.action.as_ref()),
                Some(Action::ToolCall(_))
            );
            let decision = if is_tool_call {
                aa_proto::assembly::common::v1::Decision::Redact
            } else {
                aa_proto::assembly::common::v1::Decision::Allow
            };
            Ok(Response::new(CheckActionResponse {
                decision: decision as i32,
                redact: is_tool_call.then(Default::default),
                ..Default::default()
            }))
        }

        async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }

        type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

        async fn op_control_stream(
            &self,
            _req: Request<OpControlSubscribeRequest>,
        ) -> Result<Response<Self::OpControlStreamStream>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    /// Bind a gateway that answers `Redact` to MCP `tools/call`.
    pub async fn spawn_redacting_gateway() -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(RedactToolCalls))
                .serve(addr)
                .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        format!("http://{addr}")
    }

    /// Allows every `CheckAction` unconditionally. Neither `DenyEverything`
    /// nor `AllowOnlyNetworkHost` lets an MCP `tools/call` reach the upstream
    /// (AAASM-5645 needs a real, decoded response body from a live upstream,
    /// which requires the call itself to be allowed).
    #[derive(Default)]
    struct AllowEverything;

    #[tonic::async_trait]
    impl PolicyService for AllowEverything {
        async fn check_action(
            &self,
            _req: Request<CheckActionRequest>,
        ) -> Result<Response<CheckActionResponse>, Status> {
            Ok(Response::new(CheckActionResponse {
                decision: aa_proto::assembly::common::v1::Decision::Allow as i32,
                ..Default::default()
            }))
        }

        async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }

        type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

        async fn op_control_stream(
            &self,
            _req: Request<OpControlSubscribeRequest>,
        ) -> Result<Response<Self::OpControlStreamStream>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    /// Allows every `tools/call`; answers `verdict` to a `ToolResult` whose body
    /// carries the gateway-only marker, `Allow` otherwise (`Error` fails the RPC).
    #[derive(Clone, Copy)]
    pub enum ResultVerdict {
        Redact,
        Deny,
        Allow,
        Error,
        /// `tools/call` check FAILS (RPC error); a result with the marker is Redact.
        CallErrorResultRedact,
        /// `tools/call` check FAILS; every result is Allow.
        CallErrorResultAllow,
    }

    struct JudgeResults(ResultVerdict);

    #[tonic::async_trait]
    impl PolicyService for JudgeResults {
        async fn check_action(
            &self,
            req: Request<CheckActionRequest>,
        ) -> Result<Response<CheckActionResponse>, Status> {
            use aa_proto::assembly::common::v1::Decision;
            use aa_proto::assembly::policy::v1::action_context::Action;
            let decision = match req.get_ref().context.as_ref().and_then(|c| c.action.as_ref()) {
                Some(Action::ToolCall(_))
                    if matches!(
                        self.0,
                        ResultVerdict::CallErrorResultRedact | ResultVerdict::CallErrorResultAllow
                    ) =>
                {
                    return Err(Status::resource_exhausted("stub request failure"));
                }
                Some(Action::ToolResult(r)) => {
                    if matches!(self.0, ResultVerdict::Error) {
                        return Err(Status::internal("stub result failure"));
                    }
                    let marked = r
                        .result_json
                        .windows(super::POLICY_ONLY_VALUE.len())
                        .any(|w| w == super::POLICY_ONLY_VALUE.as_bytes());
                    match (marked, self.0) {
                        (true, ResultVerdict::Redact | ResultVerdict::CallErrorResultRedact) => Decision::Redact,
                        (true, ResultVerdict::Deny) => Decision::Deny,
                        _ => Decision::Allow,
                    }
                }
                _ => Decision::Allow,
            };
            Ok(Response::new(CheckActionResponse {
                decision: decision as i32,
                redact: matches!(decision, Decision::Redact).then(Default::default),
                reason: "stub result verdict".into(),
                ..Default::default()
            }))
        }

        async fn batch_check(&self, _req: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
            Err(Status::unimplemented("stub"))
        }

        type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

        async fn op_control_stream(
            &self,
            _req: Request<OpControlSubscribeRequest>,
        ) -> Result<Response<Self::OpControlStreamStream>, Status> {
            Err(Status::unimplemented("stub"))
        }
    }

    pub async fn spawn_result_judging_gateway(verdict: ResultVerdict) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(JudgeResults(verdict)))
                .serve(addr)
                .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        format!("http://{addr}")
    }

    /// Bind a gateway that allows everything.
    pub async fn spawn_allowing_gateway() -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(AllowEverything))
                .serve(addr)
                .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        format!("http://{addr}")
    }
}

// ── the control that keeps the refusal assertions honest ───────────────────

/// The mutation AC2 names explicitly: a test that only ever sees a refusal
/// cannot notice a forwarded variant being persisted in its place.
///
/// One proxy, one sink, two requests. The first is refused by the denylist; the
/// second is forwarded to a live upstream and genuinely answered. If the
/// refusal branch ever persisted forwarding evidence the two records would
/// become indistinguishable, and this test — unlike a per-refusal count — says
/// so.
#[tokio::test]
async fn a_refusal_and_a_forward_are_distinguishable_on_one_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let upstream = live_tls_upstream().await;
    let (proxy, mut audit) = start_proxy(
        Fixture {
            denied_hosts: vec![DENIED_HOST.to_string()],
            upstream_override: Some(upstream),
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    // 1. Refused before any dial.
    assert!(open_tunnel(proxy, DENIED_HOST).await.is_err());
    let refusal = next_entry(&mut audit).await;

    // 2. Allowed, and the bytes really go: the upstream answers 200.
    let tunnel = open_tunnel(proxy, LLM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, LLM_HOST, &post(LLM_HOST, "/v1/chat/completions", "hello")).await;
    assert!(
        response.contains("200 OK"),
        "the second request must reach a live upstream, got: {response:?}"
    );

    // A clean body decides nothing, so the forward writes no decision event —
    // which is itself the assertion: the sink holds the refusal and nothing
    // else, and the refusal is the shape that says the bytes stayed.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut rest = Vec::new();
    while let Ok(entry) = audit.try_recv() {
        rest.push(entry);
    }
    assert!(
        rest.iter().all(|e| !e.execution.establishes_non_transmission()),
        "a forwarded request produced prevention evidence: {rest:#?}"
    );
    assert!(refusal.execution.establishes_non_transmission());
    assert_eq!(refusal.host, DENIED_HOST);
}

// ── Chunked MCP response is decoded, not silently emptied (AAASM-5645) ─────

/// Before AAASM-5645, `read_http_response` derived the body length from
/// `Content-Length` alone and defaulted to zero when the header was absent —
/// a `Transfer-Encoding: chunked` MCP response therefore reached the client
/// as a well-formed `200` with an empty body. Modelled on
/// `an_mcp_tools_call_deny_persists_a_refusal`, but the gateway allows the
/// call so the response actually reaches `read_http_response`.
///
/// Asserts both directions the AC requires: the full marker (spanning a
/// chunk boundary) reaches the client, **and** the status is `200`, not
/// `502` — the fail-closed "withhold" option the ticket deliberately did not
/// take. A test that only checked one of these would also pass if the fix
/// had instead withheld every chunked response with the existing JSON-RPC
/// error.
#[tokio::test]
async fn an_mcp_response_using_chunked_transfer_encoding_is_relayed_whole() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_allowing_gateway().await;
    let upstream = chunked_tls_upstream().await;
    let (proxy, _audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(gateway),
            upstream_override: Some(upstream),
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_tools_call_body())).await;

    assert!(
        response.contains("200"),
        "an allowed chunked MCP response must not be downgraded to a fail-closed withhold, got: {response:?}"
    );
    assert!(
        !response.contains("502"),
        "a chunked response must be decoded, not withheld as unparseable, got: {response:?}"
    );
    assert!(
        response.contains("chunk-boundary-marker"),
        "the full body, reassembled across the chunk boundary, must reach the client, got: {response:?}"
    );
}

// ── MCP gateway Redact is fail-closed unless the proxy can redact (AAASM-6353) ──

const BUILTIN_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
/// A value only a gateway policy pattern would match: no built-in rule in the
/// proxy's scanner fires on it.
const POLICY_ONLY_VALUE: &str = "ACME-PROJECT-ZEBRA-7731";

fn mcp_body_with(value: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"send_note","arguments":{{"text":"{value}"}}}}}}"#
    )
}

async fn redact_fixture_proxy(
    gateway: String,
    upstream: SocketAddr,
    dir: &std::path::Path,
) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
    redact_fixture_proxy_with(gateway, upstream, dir, CredentialAction::RedactOnly).await
}

async fn redact_fixture_proxy_with(
    gateway: String,
    upstream: SocketAddr,
    dir: &std::path::Path,
    action: CredentialAction,
) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
    start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(gateway),
            upstream_override: Some(upstream),
            credential_action: Some(action),
            ..Fixture::default()
        },
        dir,
    )
    .await
}

#[tokio::test]
async fn gateway_redact_with_a_policy_only_value_is_denied_and_never_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_redacting_gateway().await;
    let (upstream, received) = recording_tls_upstream().await;
    let (proxy, _audit) = redact_fixture_proxy(gateway, upstream, dir.path()).await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(
        tunnel,
        MITM_HOST,
        &post(MITM_HOST, "/mcp", &mcp_body_with(POLICY_ONLY_VALUE)),
    )
    .await;

    assert!(
        response.contains("cannot apply"),
        "the client must get a JSON-RPC error naming the unappliable redaction, got: {response:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert!(
        received.lock().unwrap().is_empty(),
        "nothing may reach upstream, upstream saw: {:?}",
        String::from_utf8_lossy(&received.lock().unwrap())
    );
}

/// Gateway Redact must be denied and nothing may reach upstream, for `body`
/// under scanner action `action`.
async fn assert_redact_denied_and_not_forwarded(body: &str, action: CredentialAction) {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_redacting_gateway().await;
    let (upstream, received) = recording_tls_upstream().await;
    let (proxy, _audit) = redact_fixture_proxy_with(gateway, upstream, dir.path(), action).await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", body)).await;

    assert!(
        response.contains("cannot apply"),
        "{action:?}: the client must get the fail-closed JSON-RPC error, got: {response:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let saw = received.lock().unwrap().clone();
    assert!(
        saw.is_empty(),
        "{action:?}: nothing may reach upstream, upstream saw: {:?}",
        String::from_utf8_lossy(&saw)
    );
}

/// A built-in secret alone is also denied: the proxy finding something does not
/// show it covered what the gateway found.
#[tokio::test]
async fn gateway_redact_with_a_builtin_only_secret_is_denied() {
    assert_redact_denied_and_not_forwarded(&mcp_body_with(BUILTIN_SECRET), CredentialAction::RedactOnly).await;
}

/// Regression for the review exploit: one body carrying a built-in secret AND a
/// gateway-only value. A "proxy scan redacted something" predicate would forward
/// it with the gateway-only value raw.
#[tokio::test]
async fn gateway_redact_with_a_mixed_body_is_denied_not_partially_redacted() {
    let mixed = mcp_body_with(&format!("{BUILTIN_SECRET} {POLICY_ONLY_VALUE}"));
    assert_redact_denied_and_not_forwarded(&mixed, CredentialAction::RedactOnly).await;
}

#[tokio::test]
async fn gateway_redact_is_denied_under_credential_action_block() {
    let mixed = mcp_body_with(&format!("{BUILTIN_SECRET} {POLICY_ONLY_VALUE}"));
    assert_redact_denied_and_not_forwarded(&mixed, CredentialAction::Block).await;
}

#[tokio::test]
async fn gateway_redact_is_denied_under_credential_action_alert_only() {
    assert_redact_denied_and_not_forwarded(&mcp_body_with(POLICY_ONLY_VALUE), CredentialAction::AlertOnly).await;
}

/// Paired control for the test above: the SAME body under gateway Allow is
/// forwarded, so the deny there is caused by the Redact decision and not by
/// the body or the fixture.
#[tokio::test]
async fn the_same_policy_only_body_under_gateway_allow_is_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let gateway = gateway_stub::spawn_allowing_gateway().await;
    let (upstream, received) = recording_tls_upstream().await;
    let (proxy, _audit) = redact_fixture_proxy(gateway, upstream, dir.path()).await;

    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let _ = mitm_send(
        tunnel,
        MITM_HOST,
        &post(MITM_HOST, "/mcp", &mcp_body_with(POLICY_ONLY_VALUE)),
    )
    .await;

    let upstream_saw = String::from_utf8_lossy(&received.lock().unwrap()).into_owned();
    assert!(
        upstream_saw.contains(POLICY_ONLY_VALUE),
        "under Allow the body is forwarded unchanged, upstream saw: {upstream_saw:?}"
    );
}

// ── Content-Encoded MCP request bodies are evaluated, not skipped (AAASM-6354) ──

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

fn zlib_bytes(plain: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

fn post_encoded(host: &str, encoding: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {host}\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

/// Send one MCP `tools/call` body (already encoded) through a proxy backed by
/// `gateway` and return (client response, bytes that reached upstream).
async fn send_encoded_mcp(gateway: String, encoding: &str, body: &[u8]) -> (String, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = recording_tls_upstream().await;
    let (proxy, _audit) = redact_fixture_proxy_with(gateway, upstream, dir.path(), CredentialAction::AlertOnly).await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send_bytes(tunnel, MITM_HOST, &post_encoded(MITM_HOST, encoding, body)).await;
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    let seen = received.lock().unwrap().clone();
    (response, seen)
}

#[tokio::test]
async fn a_gzip_mcp_call_the_gateway_denies_is_denied_and_never_forwarded() {
    let body = mcp_body_with("anything");
    let (response, seen) = send_encoded_mcp(
        gateway_stub::spawn_denying_gateway().await,
        "gzip",
        &gzip_bytes(body.as_bytes()),
    )
    .await;
    assert!(
        response.contains("-32000"),
        "gateway Deny must reach the client, got: {response:?}"
    );
    assert!(
        seen.is_empty(),
        "a denied call must not reach upstream, saw {} bytes",
        seen.len()
    );
}

#[tokio::test]
async fn a_deflate_mcp_call_the_gateway_denies_is_denied_and_never_forwarded() {
    let body = mcp_body_with("anything");
    let (response, seen) = send_encoded_mcp(
        gateway_stub::spawn_denying_gateway().await,
        "deflate",
        &zlib_bytes(body.as_bytes()),
    )
    .await;
    assert!(response.contains("-32000"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

#[tokio::test]
async fn a_gzip_mcp_call_the_gateway_redacts_is_denied_not_forwarded_raw() {
    let body = mcp_body_with(POLICY_ONLY_VALUE);
    let (response, seen) = send_encoded_mcp(
        gateway_stub::spawn_redacting_gateway().await,
        "gzip",
        &gzip_bytes(body.as_bytes()),
    )
    .await;
    assert!(response.contains("cannot apply"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

#[tokio::test]
async fn an_undecodable_mcp_body_encoding_is_denied_fail_closed() {
    for (encoding, body) in [
        ("br", mcp_body_with("x").into_bytes()),
        ("zstd", mcp_body_with("x").into_bytes()),
        ("gzip, br", gzip_bytes(mcp_body_with("x").as_bytes())),
        ("gzip", b"not actually gzip".to_vec()),
    ] {
        let (response, seen) = send_encoded_mcp(gateway_stub::spawn_allowing_gateway().await, encoding, &body).await;
        assert!(
            response.contains("cannot be enforced") || response.contains("cannot decode"),
            "{encoding}: must be rejected, got: {response:?}"
        );
        assert!(seen.is_empty(), "{encoding}: saw {} bytes upstream", seen.len());
    }
}

/// Controls: the same call is forwarded when the gateway allows it, whether
/// plain, `identity`, or gzip - so the denials above come from the gateway
/// verdict on the decoded call, not from a blanket refusal of encoded bodies.
#[tokio::test]
async fn an_allowed_mcp_call_is_forwarded_plain_identity_and_gzip() {
    let body = mcp_body_with("harmless");
    for (encoding, wire) in [
        ("identity", body.clone().into_bytes()),
        ("gzip", gzip_bytes(body.as_bytes())),
    ] {
        let (response, seen) = send_encoded_mcp(gateway_stub::spawn_allowing_gateway().await, encoding, &wire).await;
        assert!(
            !seen.is_empty(),
            "{encoding}: an allowed call must reach upstream, got: {response:?}"
        );
    }
}

// ── MCP response direction is evaluated by the gateway (AAASM-6355) ──────────

/// A TLS upstream answering one fixed body (optionally `Content-Encoding`-ed).
async fn fixed_body_tls_upstream(body: Vec<u8>, content_encoding: Option<&'static str>) -> SocketAddr {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
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
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut chunk = [0u8; 8192];
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), tls.read(&mut chunk)).await;
                let enc = content_encoding
                    .map(|e| format!("Content-Encoding: {e}\r\n"))
                    .unwrap_or_default();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{enc}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

/// Send an allowed `tools/call` whose upstream answers `upstream_body`; return
/// what the client received.
async fn client_view_of_response(
    gateway: String,
    upstream_body: Vec<u8>,
    content_encoding: Option<&'static str>,
) -> String {
    let dir = tempfile::tempdir().unwrap();
    let upstream = fixed_body_tls_upstream(upstream_body, content_encoding).await;
    let (proxy, _audit) = redact_fixture_proxy_with(gateway, upstream, dir.path(), CredentialAction::AlertOnly).await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_body_with("harmless"))).await
}

fn result_body(text: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{text}"}}]}}}}"#).into_bytes()
}

#[tokio::test]
async fn a_gateway_only_value_in_a_response_is_withheld_when_the_gateway_redacts_it() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        result_body(POLICY_ONLY_VALUE),
        None,
    )
    .await;
    assert!(
        !view.contains(POLICY_ONLY_VALUE),
        "the gateway-only value reached the client: {view:?}"
    );
    assert!(!view.contains("200 OK"), "the response must be withheld, got: {view:?}");
}

#[tokio::test]
async fn a_gateway_only_value_in_a_response_is_withheld_when_the_gateway_denies_it() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Deny).await,
        result_body(POLICY_ONLY_VALUE),
        None,
    )
    .await;
    assert!(!view.contains(POLICY_ONLY_VALUE), "got: {view:?}");
    assert!(!view.contains("200 OK"), "got: {view:?}");
}

#[tokio::test]
async fn an_encoded_response_carrying_a_gateway_only_value_is_withheld() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        gzip_bytes(&result_body(POLICY_ONLY_VALUE)),
        Some("gzip"),
    )
    .await;
    assert!(
        !view.contains("200 OK"),
        "an encoded body the gateway objects to must be withheld, got: {view:?}"
    );
}

#[tokio::test]
async fn a_mixed_response_is_withheld_not_partially_redacted() {
    use gateway_stub::ResultVerdict;
    // The proxy redacts the built-in secret itself; the gateway still sees the
    // policy-only value in what would be sent, so the response is withheld.
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        result_body(&format!("{BUILTIN_SECRET} and {POLICY_ONLY_VALUE}")),
        None,
    )
    .await;
    assert!(
        !view.contains(POLICY_ONLY_VALUE) && !view.contains(BUILTIN_SECRET),
        "got: {view:?}"
    );
    assert!(!view.contains("200 OK"), "got: {view:?}");
}

#[tokio::test]
async fn a_failed_response_evaluation_withholds_fail_closed() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Error).await,
        result_body("harmless"),
        None,
    )
    .await;
    assert!(
        !view.contains("200 OK"),
        "an unevaluable response must not be forwarded, got: {view:?}"
    );
}

/// Controls: the withholds above come from the gateway's verdict, not from a
/// blanket refusal. Same upstream bodies, forwarded when the gateway allows.
#[tokio::test]
async fn responses_the_gateway_allows_are_forwarded() {
    use gateway_stub::ResultVerdict;
    for (body, enc) in [
        (result_body(POLICY_ONLY_VALUE), None),
        (gzip_bytes(&result_body("harmless")), Some("gzip")),
        (result_body("harmless"), None),
    ] {
        let view = client_view_of_response(
            gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
            body,
            enc,
        )
        .await;
        assert!(
            view.contains("200 OK"),
            "an allowed response must be forwarded, got: {view:?}"
        );
    }
}

/// The proxy's own built-in redaction still applies before the gateway sees the
/// body, so a built-in secret alone is redacted and forwarded (no regression).
#[tokio::test]
async fn a_builtin_secret_in_a_response_is_still_redacted_and_forwarded() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        result_body(BUILTIN_SECRET),
        None,
    )
    .await;
    assert!(view.contains("200 OK"), "got: {view:?}");
    assert!(
        !view.contains(BUILTIN_SECRET),
        "the built-in secret must be redacted, got: {view:?}"
    );
}

/// `mcp_fail_open` is the operator opt-in for forwarding a `tools/call` when the
/// gateway is unreachable. It must not extend to the response direction.
#[tokio::test]
async fn a_failed_response_evaluation_is_withheld_even_with_mcp_fail_open() {
    use gateway_stub::ResultVerdict;
    let dir = tempfile::tempdir().unwrap();
    let upstream = fixed_body_tls_upstream(result_body(POLICY_ONLY_VALUE), None).await;
    let (proxy, _audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(gateway_stub::spawn_result_judging_gateway(ResultVerdict::Error).await),
            upstream_override: Some(upstream),
            credential_action: Some(CredentialAction::AlertOnly),
            mcp_fail_open: true,
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let view = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_body_with("harmless"))).await;
    assert!(!view.contains(POLICY_ONLY_VALUE), "got: {view:?}");
    assert!(
        !view.contains("200 OK"),
        "fail-open must not forward an unevaluated response, got: {view:?}"
    );
}

/// A gzip body that expands past the proxy's cap is un-inspectable and withheld,
/// even though the gateway would allow everything.
#[tokio::test]
async fn a_decompression_bomb_response_is_withheld_not_forwarded() {
    use gateway_stub::ResultVerdict;
    let bomb = gzip_bytes(&vec![b'a'; 70 * 1024 * 1024]);
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        bomb,
        Some("gzip"),
    )
    .await;
    assert!(
        !view.contains("200 OK"),
        "an over-cap encoded response must be withheld, got a forward"
    );
}

// ── review findings on the AAASM-6354/6355 stack (F1-F4) ─────────────────────

fn escaped_policy_value_response() -> Vec<u8> {
    // The policy-only value with its first character sent as a JSON `\u0041`
    // escape: invisible to a raw-text match, decoded by every JSON client.
    let escaped = POLICY_ONLY_VALUE.replacen('A', "\\u0041", 1);
    result_body(&escaped)
}

/// F1: the *request* check fails under `mcp_fail_open` (the call is forwarded
/// unevaluated, per the documented opt-in) - the response must still be
/// evaluated, and withheld when the gateway objects.
#[tokio::test]
async fn fail_open_request_forward_still_evaluates_and_withholds_the_response() {
    use gateway_stub::ResultVerdict;
    let dir = tempfile::tempdir().unwrap();
    let upstream = fixed_body_tls_upstream(result_body(POLICY_ONLY_VALUE), None).await;
    let (proxy, _audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(
                gateway_stub::spawn_result_judging_gateway(ResultVerdict::CallErrorResultRedact).await,
            ),
            upstream_override: Some(upstream),
            credential_action: Some(CredentialAction::AlertOnly),
            mcp_fail_open: true,
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let view = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_body_with("harmless"))).await;
    assert!(!view.contains(POLICY_ONLY_VALUE), "got: {view:?}");
    assert!(
        !view.contains("200 OK"),
        "an unevaluated request must not unlock an unevaluated response, got: {view:?}"
    );
}

/// F1 control: same fail-open request forward, gateway healthy for results and
/// allowing them - the documented request-side opt-in still works.
#[tokio::test]
async fn fail_open_request_forward_still_delivers_an_allowed_response() {
    use gateway_stub::ResultVerdict;
    let dir = tempfile::tempdir().unwrap();
    let upstream = fixed_body_tls_upstream(result_body("harmless"), None).await;
    let (proxy, _audit) = start_proxy(
        Fixture {
            mitm_hosts: vec![MITM_HOST.to_string()],
            gateway_endpoint: Some(
                gateway_stub::spawn_result_judging_gateway(ResultVerdict::CallErrorResultAllow).await,
            ),
            upstream_override: Some(upstream),
            credential_action: Some(CredentialAction::AlertOnly),
            mcp_fail_open: true,
            ..Fixture::default()
        },
        dir.path(),
    )
    .await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let view = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_body_with("harmless"))).await;
    assert!(view.contains("200 OK"), "got: {view:?}");
}

/// F2 (request): `gzip("") ++ gzip(tools/call)` decoded to nothing with a
/// first-member-only decoder, skipping CheckAction while an upstream that
/// inflates every member would run the call.
#[tokio::test]
async fn a_multi_member_gzip_mcp_call_is_evaluated_not_skipped() {
    let body = mcp_body_with("anything");
    let mut wire = gzip_bytes(b"");
    wire.extend_from_slice(&gzip_bytes(body.as_bytes()));
    let (response, seen) = send_encoded_mcp(gateway_stub::spawn_denying_gateway().await, "gzip", &wire).await;
    assert!(
        response.contains("-32000"),
        "the gateway Deny must apply to the later member, got: {response:?}"
    );
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

/// F2: bytes after the stream are not inspectable, so they are refused.
#[tokio::test]
async fn trailing_bytes_after_a_gzip_mcp_body_are_refused() {
    let mut wire = gzip_bytes(mcp_body_with("x").as_bytes());
    wire.extend_from_slice(b"TRAILINGGARBAGE");
    let (response, seen) = send_encoded_mcp(gateway_stub::spawn_allowing_gateway().await, "gzip", &wire).await;
    assert!(
        response.contains("cannot decode") || response.contains("cannot be enforced"),
        "got: {response:?}"
    );
    assert!(seen.is_empty());
}

/// F2 (response): a multi-member gzip response hides the secret in a later member.
#[tokio::test]
async fn a_multi_member_gzip_response_is_fully_decoded_and_withheld() {
    use gateway_stub::ResultVerdict;
    let mut wire = gzip_bytes(b"");
    wire.extend_from_slice(&gzip_bytes(&result_body(POLICY_ONLY_VALUE)));
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        wire,
        Some("gzip"),
    )
    .await;
    assert!(!view.contains("200 OK"), "got: {view:?}");
}

/// F3: two `Content-Encoding` headers are a layered encoding to the client.
#[tokio::test]
async fn duplicate_content_encoding_headers_on_a_response_are_withheld() {
    use gateway_stub::ResultVerdict;
    let dir = tempfile::tempdir().unwrap();
    let body = gzip_bytes(&gzip_bytes(&result_body(POLICY_ONLY_VALUE)));
    let upstream =
        fixed_body_tls_upstream_raw_headers(body, "Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n").await;
    let (proxy, _audit) = redact_fixture_proxy_with(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        upstream,
        dir.path(),
        CredentialAction::AlertOnly,
    )
    .await;
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let view = mitm_send(tunnel, MITM_HOST, &post(MITM_HOST, "/mcp", &mcp_body_with("harmless"))).await;
    assert!(
        !view.contains("200 OK"),
        "a layered encoding must be withheld even if the gateway would allow, got a forward"
    );
}

/// F3 (request).
#[tokio::test]
async fn duplicate_content_encoding_headers_on_a_request_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = recording_tls_upstream().await;
    let (proxy, _audit) = redact_fixture_proxy_with(
        gateway_stub::spawn_allowing_gateway().await,
        upstream,
        dir.path(),
        CredentialAction::AlertOnly,
    )
    .await;
    let body = gzip_bytes(&gzip_bytes(mcp_body_with("x").as_bytes()));
    let mut req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {MITM_HOST}\r\nContent-Encoding: gzip\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(&body);
    let tunnel = open_tunnel(proxy, MITM_HOST).await.expect("the CONNECT is allowed");
    let response = mitm_send_bytes(tunnel, MITM_HOST, &req).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        response.contains("cannot decode") || response.contains("cannot be enforced"),
        "got: {response:?}"
    );
    assert!(received.lock().unwrap().is_empty());
}

/// F4: a value delivered as JSON `\uXXXX` escapes is judged as the client will
/// read it. Control: the unescaped body is withheld too, and a clean one is not.
#[tokio::test]
async fn a_json_escaped_gateway_only_value_in_a_response_is_withheld() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        escaped_policy_value_response(),
        None,
    )
    .await;
    assert!(
        !view.contains("200 OK"),
        "an escaped value must not slip past the raw-text match, got: {view:?}"
    );
}

/// A TLS upstream answering `body` with caller-supplied raw header lines.
async fn fixed_body_tls_upstream_raw_headers(body: Vec<u8>, extra_headers: &'static str) -> SocketAddr {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
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
            let body = body.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut chunk = [0u8; 8192];
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), tls.read(&mut chunk)).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

// ── review round 2: duplicate keys, BOM/invalid bytes, lenient request parse (V1/V2/V4/L1) ──

fn bytes_of(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// A response whose `text` key appears twice: serde keeps the LAST, other JSON
/// parsers may keep either, and the forwarded bytes carry both.
fn duplicate_key_response(first: &str) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"text":"{first}","text":"ok"}}}}"#).into_bytes()
}

/// V1: the built-in secret sits in the shadowed first `text`. The normalised
/// body is clean, so only a raw scan sees it; it must not reach the client.
#[tokio::test]
async fn a_builtin_secret_in_a_shadowed_duplicate_key_is_redacted() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        duplicate_key_response(BUILTIN_SECRET),
        None,
    )
    .await;
    assert!(
        !view.contains(BUILTIN_SECRET),
        "the shadowed secret reached the client: {view:?}"
    );
}

/// V1 control: the same duplicate-key shape without a secret is forwarded, so
/// the redaction above comes from the secret and not from duplicate keys.
#[tokio::test]
async fn a_clean_duplicate_key_response_is_forwarded() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        duplicate_key_response("harmless"),
        None,
    )
    .await;
    assert!(view.contains("200 OK"), "got: {view:?}");
}

/// V1: a gateway-only value in the shadowed key is judged on the raw form.
#[tokio::test]
async fn a_gateway_only_value_in_a_shadowed_duplicate_key_is_withheld() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        duplicate_key_response(POLICY_ONLY_VALUE),
        None,
    )
    .await;
    assert!(
        !view.contains(POLICY_ONLY_VALUE) && !view.contains("200 OK"),
        "got: {view:?}"
    );
}

/// V1 control: the identical body is forwarded when the gateway allows it.
#[tokio::test]
async fn the_same_shadowed_gateway_only_body_is_forwarded_under_allow() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        duplicate_key_response(POLICY_ONLY_VALUE),
        None,
    )
    .await;
    assert!(view.contains("200 OK"), "got: {view:?}");
}

/// V2: a BOM defeated `serde_json::from_slice`, leaving escapes undecoded.
#[tokio::test]
async fn a_bom_prefixed_escaped_gateway_only_value_is_withheld() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        bytes_of(&[BOM, &escaped_policy_value_response()]),
        None,
    )
    .await;
    assert!(
        !view.contains("200 OK"),
        "a BOM must not hide an escaped value, got: {view:?}"
    );
}

/// V2 control: a BOM-prefixed body whose escaped value is clean is forwarded.
#[tokio::test]
async fn a_bom_prefixed_escaped_clean_value_is_forwarded() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        bytes_of(&[BOM, &result_body("harmless \\u0041")]),
        None,
    )
    .await;
    assert!(view.contains("200 OK"), "got: {view:?}");
}

/// V2: one invalid UTF-8 byte elsewhere in the body must not hide an escape.
#[tokio::test]
async fn an_invalid_byte_does_not_hide_an_escaped_gateway_only_value() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        bytes_of(&[b"{\"pad\":\"\xFF\",", &escaped_policy_value_response()[1..]]),
        None,
    )
    .await;
    assert!(!view.contains("200 OK"), "got: {view:?}");
}

/// V2 control: the same invalid byte with a clean escaped value is forwarded.
#[tokio::test]
async fn an_invalid_byte_with_a_clean_escaped_value_is_forwarded() {
    use gateway_stub::ResultVerdict;
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Redact).await,
        bytes_of(&[b"{\"pad\":\"\xFF\",", &result_body("harmless \\u0041")[1..]]),
        None,
    )
    .await;
    assert!(view.contains("200 OK"), "got: {view:?}");
}

/// F4/V2: a built-in secret hidden by an escape is withheld by the proxy's own
/// scan (no gateway involved in the decision); the plain secret is redacted.
#[tokio::test]
async fn an_escaped_builtin_secret_is_withheld_not_forwarded() {
    use gateway_stub::ResultVerdict;
    let escaped = BUILTIN_SECRET.replacen('A', "\\u0041", 1);
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        bytes_of(&[BOM, &result_body(&escaped)]),
        None,
    )
    .await;
    assert!(
        !view.contains(BUILTIN_SECRET) && !view.contains("200 OK"),
        "got: {view:?}"
    );
}

/// L1: redacting a built-in secret must not re-serialise the rest of the body.
#[tokio::test]
async fn redaction_keeps_big_integers_byte_faithful() {
    use gateway_stub::ResultVerdict;
    let body =
        format!(r#"{{"jsonrpc":"2.0","id":123456789012345678901234567890,"result":{{"text":"{BUILTIN_SECRET}"}}}}"#);
    let view = client_view_of_response(
        gateway_stub::spawn_result_judging_gateway(ResultVerdict::Allow).await,
        body.into_bytes(),
        None,
    )
    .await;
    assert!(!view.contains(BUILTIN_SECRET), "got: {view:?}");
    assert!(
        view.contains("123456789012345678901234567890"),
        "the integer must keep every digit, got: {view:?}"
    );
}

/// Send `body` (identity-encoded) as an MCP request; return (client view, bytes
/// that reached upstream).
async fn send_raw_mcp(gateway: String, body: &[u8]) -> (String, Vec<u8>) {
    send_encoded_mcp(gateway, "identity", body).await
}

/// V4: a BOM-prefixed `tools/call` is evaluated, so a denying gateway stops it.
#[tokio::test]
async fn a_bom_prefixed_mcp_call_is_denied_and_never_forwarded() {
    let (response, seen) = send_raw_mcp(
        gateway_stub::spawn_denying_gateway().await,
        &bytes_of(&[BOM, mcp_body_with("x").as_bytes()]),
    )
    .await;
    assert!(response.contains("-32000"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

/// V4: one 0xFF byte inside an argument string must not turn the call into
/// "not JSON".
#[tokio::test]
async fn an_invalid_byte_in_an_mcp_argument_is_still_denied() {
    let body = bytes_of(&[
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_note","arguments":{"text":"a"#,
        b"\xFF",
        br#"b"}}}"#,
    ]);
    let (response, seen) = send_raw_mcp(gateway_stub::spawn_denying_gateway().await, &body).await;
    assert!(response.contains("-32000"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

/// V4: an unparseable JSON-looking body naming `tools\/call` (escaped slash) is
/// refused rather than skipped.
#[tokio::test]
async fn an_unparseable_escaped_slash_tools_call_is_refused() {
    let body = br#"{"jsonrpc":"2.0","method":"tools\/call","params":{"name":"x" BROKEN"#;
    let (response, seen) = send_raw_mcp(gateway_stub::spawn_allowing_gateway().await, body).await;
    assert!(response.contains("cannot be enforced"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

/// V4: a well-formed `tools\/call` (escaped slash) decodes to the real method
/// and is evaluated.
#[tokio::test]
async fn a_well_formed_escaped_slash_tools_call_is_evaluated() {
    let body = mcp_body_with("x").replace("tools/call", "tools\\/call");
    let (response, seen) = send_raw_mcp(gateway_stub::spawn_denying_gateway().await, body.as_bytes()).await;
    assert!(response.contains("-32000"), "got: {response:?}");
    assert!(seen.is_empty(), "saw {} bytes upstream", seen.len());
}

/// V4 controls: the BOM, 0xFF and plain bodies reach upstream when the gateway
/// allows (evaluated, not blanket-refused), and unparseable non-MCP JSON that
/// never names `tools/call` is not refused.
#[tokio::test]
async fn allowed_lenient_mcp_bodies_and_non_mcp_garbage_are_forwarded() {
    let with_ff = bytes_of(&[
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_note","arguments":{"text":"a"#,
        b"\xFF",
        br#"b"}}}"#,
    ]);
    for (label, body) in [
        ("plain", mcp_body_with("x").into_bytes()),
        ("bom", bytes_of(&[BOM, mcp_body_with("x").as_bytes()])),
        ("0xff", with_ff),
        ("non-mcp garbage", br#"{"hello": BROKEN"#.to_vec()),
    ] {
        let (response, seen) = send_raw_mcp(gateway_stub::spawn_allowing_gateway().await, &body).await;
        assert!(!seen.is_empty(), "{label}: must reach upstream, got: {response:?}");
    }
}
