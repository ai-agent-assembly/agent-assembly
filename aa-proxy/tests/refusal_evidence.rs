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
    /// AAASM-5855: the identity `aasm run` would have exported as `AA_AGENT_ID`
    /// for this launch. `None` reproduces the pre-fix default.
    agent_id: Option<String>,
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
        credential_action: CredentialAction::AlertOnly,
        upstream_override: fixture.upstream_override,
        gateway_endpoint: fixture.gateway_endpoint,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: fixture.agent_id,
        // The mock upstreams are on loopback, which the SSRF guard would
        // (correctly) refuse in production.
        allow_private_connect_targets: !fixture.block_private_targets,
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
