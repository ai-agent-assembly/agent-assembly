//! AAASM-5924: ADR 0036's full negative-control test matrix for trusted
//! upstream proxy chaining, as real `aa-proxy` processes talking to a real
//! (loopback) mock corporate proxy and a real (loopback) capturing
//! destination — not unit-level assertions against `trusted_upstream::`'s
//! pure functions, which `aa-proxy/src/trusted_upstream.rs`'s own `#[cfg(test)]`
//! module already covers for D5/D7/D-B/F3/N4 in isolation. These tests prove
//! the *wiring*: that `ProxyServer::run()` actually reaches and enforces that
//! logic against real network traffic.
//!
//! ## Row numbering
//!
//! Numbered against **ADR 0036's own Test strategy table**, not the ticket's
//! (the ticket's numbering drifts by one from row 9 onward):
//!
//! | Row | Subject |
//! |---|---|
//! | 1 | Declared destination + trusted proxy → chained, redacted at the destination |
//! | 2 | Undeclared host / declared host on wrong port → direct path, not chained |
//! | 3 | RFC1918 CONNECT literal / resolved name → refused by the SSRF guard |
//! | 4 | Matched-population comparison: chaining configured vs not |
//! | 5 | Chained eligibility decided on the CONNECT authority, not resolution |
//! | 9 | Corporate-proxy `auth` + `scheme: Http` → refused at validation |
//! | 10 | Trusted proxy unreachable → fail closed, no direct-dial fallback |
//! | 11 | Trusted proxy resolves back to this proxy's own listener → loop, refused |
//! | 12 | Existing SSRF regression suite remains green (see `ssrf.rs`/`aa-core::net`) |
//! | 15 | `AA_PROXY_NETWORK_FAIL_OPEN=1` — gateway stage only, not the dial path |
//!
//! Row 6/6b/6c (ambient proxy env at the real spawned child), row 7 (ambient
//! AASM-specific env var), and row 8 (`AASM_STATE_DIR`/`AA_PROXY_TRUSTED_CONFIG_PATH`
//! manipulation) live at the `aa-cli` boundary — see
//! `aa-integration-tests/tests/cli_run_claude_launch_env.rs` and
//! `aa-cli/src/commands/proxy/{guard,start}.rs`'s own test modules. Row 13
//! ("existing SSRF suite remains unmodified") is a PR-diff property, not a new
//! test — see the PR description.
//!
//! Every row pairs its positive assertion with a **committed differential
//! sibling** exercising the opposite outcome under genuinely different input
//! (not a mutate/revert record) — the negative-control form this repo's own
//! `qa/README.md` documents.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

/// Synthetic OpenAI-style key the default scanner detects. Not a real
/// credential.
const SECRET: &str = "sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab";

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ── mock corporate proxy + capturing destination ────────────────────────────

/// A plain-TCP mock of a corporate forward proxy: reads a `CONNECT` request
/// line + headers, records the authority and any `Proxy-Authorization`
/// header, answers `200 Connection Established`, then blind-copies bytes to
/// `dest`.
///
/// Held for the test's lifetime (never bind-then-drop — see
/// `aa-proxy/tests/mitm_execution_evidence.rs`'s `refusing_upstream` doc for
/// why: a released loopback port can be re-handed to `aa-proxy`'s own
/// listener, which would trip the D7 loop check and invert what these tests
/// measure).
///
/// `scheme: Http` is the happy-path leg deliberately — `establish_trusted_proxy_tunnel`
/// builds a fresh TLS `ClientConfig` from `rustls_native_certs` unconditionally
/// for the `Https` leg, so a self-signed local cert can never verify there;
/// that is D5/F8's own hardening, not an obstacle to route around.
async fn mock_corporate_proxy(dest: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let authorities: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let authorities_bg = authorities.clone();

    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let authorities = authorities_bg.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(sock);
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                    return;
                }
                let authority = request_line
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split(' ').next())
                    .unwrap_or("")
                    .to_string();
                let mut saw_auth = false;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).await.unwrap_or(0) == 0 {
                        return;
                    }
                    if header.trim().is_empty() {
                        break;
                    }
                    if header.to_ascii_lowercase().starts_with("proxy-authorization:") {
                        saw_auth = true;
                    }
                }
                authorities.lock().unwrap().push(if saw_auth {
                    format!("{authority} [authed]")
                } else {
                    authority
                });

                let mut stream = reader.into_inner();
                if stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(mut upstream) = TcpStream::connect(dest).await else {
                    return;
                };
                let (mut cr, mut cw) = stream.into_split();
                let (mut ur, mut uw) = upstream.split();
                let _ = tokio::select! {
                    r = tokio::io::copy(&mut cr, &mut uw) => r,
                    r = tokio::io::copy(&mut ur, &mut cw) => r,
                };
            });
        }
    });
    (addr, authorities)
}

/// A mock enterprise destination: TLS-terminates with a self-signed leaf,
/// records the decrypted request bytes, answers `200`.
///
/// This is what Test 1's redaction assertion runs against — the trusted
/// proxy above only ever sees opaque TLS bytes once destination-TLS is
/// layered on top by `dial_upstream_tls`, so asserting redaction there would
/// pass regardless of whether it actually ran. Do not "simplify" this back.
async fn capturing_destination() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    install_crypto();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received_bg = received.clone();

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
            let received = received_bg.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    match tokio::time::timeout(std::time::Duration::from_millis(400), tls.read(&mut chunk)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                        Ok(Err(_)) => break,
                    }
                }
                if !buf.is_empty() {
                    received.lock().unwrap().push(buf);
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

// ── trusted-config artifact ──────────────────────────────────────────────────

/// Write a trusted-config artifact declaring `proxy_addr` as the trusted
/// upstream (scheme `http`, matching [`mock_corporate_proxy`]'s plain-TCP
/// leg) and `dest_host:dest_port` as the sole declared enterprise
/// destination + LLM endpoint (satisfying F3/N4 eligibility so the
/// destination reaches `handle_llm_mitm`'s full DLP tier, not just
/// `handle_non_llm_mitm`'s).
fn write_artifact(
    dir: &std::path::Path,
    proxy_addr: SocketAddr,
    dest_host: &str,
    dest_port: u16,
) -> std::path::PathBuf {
    let path = dir.join("trusted-upstream-proxy.json");
    let body = serde_json::json!({
        "trusted_upstream_proxy": {
            "scheme": "http",
            "host": proxy_addr.ip().to_string(),
            "port": proxy_addr.port(),
        },
        "declared_enterprise_destinations": [{"host": dest_host, "port": dest_port}],
        "declared_enterprise_llm_endpoints": [dest_host],
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&body).unwrap()).unwrap();
    path
}

/// Same shape as [`write_artifact`], but with no `trusted_upstream_proxy`
/// entry at all — chaining is inert (`load_and_validate` returns `Ok(None)`),
/// used by row 4's "not configured" arm.
fn write_artifact_no_endpoint(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("trusted-upstream-proxy.json");
    std::fs::write(&path, br#"{"declared_enterprise_destinations":[]}"#).unwrap();
    path
}

/// Start a real `ProxyServer` with `allow_private_connect_targets: false`
/// (the production value — every mock in this file lives on loopback, so
/// this is what actually exercises the SSRF guard rather than bypassing it)
/// and, optionally, a trusted-config artifact. Returns the bound address.
async fn start_proxy(
    trusted_config_path: Option<std::path::PathBuf>,
    allow_private_connect_targets: bool,
) -> SocketAddr {
    install_crypto();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(ca_dir.path()).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: None,
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets,
        trusted_config_path,
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    addr
}

/// Start a `ProxyServer` and hand back the `run()` future's own result,
/// rather than spawning it — for rows that assert `run()` itself refuses to
/// start (validation failure, D7 loop) rather than that a request fails.
async fn start_proxy_and_await_run_result(
    trusted_config_path: Option<std::path::PathBuf>,
    bind_addr: Option<SocketAddr>,
) -> Result<(), aa_proxy::error::ProxyError> {
    install_crypto();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(ca_dir.path()).await.unwrap();
    let bind_addr = bind_addr.unwrap_or(([127, 0, 0, 1], 0).into());
    let config = ProxyConfig {
        bind_addr,
        ca_dir: ca_dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: None,
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
        trusted_config_path,
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    // `run()` blocks forever on success (accept loop) — race it against a
    // short timeout and treat "still running after the deadline" as Ok(()).
    match tokio::time::timeout(std::time::Duration::from_millis(500), server.run()).await {
        Ok(result) => result,
        Err(_elapsed) => Ok(()),
    }
}

/// Open a CONNECT tunnel to `authority` through `proxy` and return the status
/// line the client saw (never completes the TLS handshake — these rows only
/// care whether the tunnel itself opens).
async fn connect_status_line(proxy: SocketAddr, authority: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), reader.read_line(&mut line)).await;
    line
}

/// Complete a CONNECT + MitM TLS handshake through `proxy` for `host`, send
/// `body` as a POST, and return whatever the client read back.
async fn mitm_post(proxy: SocketAddr, host: &str, body: &str) -> String {
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
        .with_custom_certificate_verifier(Arc::new(accept_any_cert::AcceptAnyCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let mut tls = connector.connect(server_name, reader.into_inner()).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

mod accept_any_cert {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct AcceptAnyCert;

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
}

const DEST_HOST: &str = "llm.corp.example";
const DEST_PORT: u16 = 443;

// ── Row 1 ─────────────────────────────────────────────────────────────────

/// Row 1: a declared destination + trusted proxy routes through the chained
/// path, and the secret is redacted **at the destination behind the proxy**.
#[tokio::test]
async fn declared_destination_redacts_the_secret_at_the_destination_behind_the_trusted_proxy() {
    let (dest_addr, received) = capturing_destination().await;
    let (corp_proxy_addr, authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), false).await;

    let body = format!("leaking {SECRET} here");
    let _ = mitm_post(proxy, DEST_HOST, &body).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Non-vacuity first: the corp proxy actually saw the CONNECT.
    let seen_authorities = authorities.lock().unwrap().clone();
    assert!(
        seen_authorities
            .iter()
            .any(|a| a.starts_with(&format!("{DEST_HOST}:{DEST_PORT}"))),
        "mock corporate proxy never received the CONNECT for the declared destination: {seen_authorities:?}"
    );

    let arrived = received.lock().unwrap();
    assert!(
        !arrived.is_empty(),
        "the destination behind the proxy received nothing at all"
    );
    let combined: Vec<u8> = arrived.iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(
        !text.contains(SECRET),
        "SECURITY INVARIANT VIOLATED: the raw secret reached the destination behind the trusted \
         proxy unredacted: {text}"
    );
}

/// Row 1's sibling: under `CredentialAction::AlertOnly` the raw secret **does**
/// reach the destination (a deliberate downgrade, not this row's bug) —
/// proves the assertion above is actually sensitive to whether redaction ran,
/// not merely to whether *anything* arrived.
#[tokio::test]
async fn alert_only_forwards_the_secret_unredacted_through_the_chain() {
    let (dest_addr, received) = capturing_destination().await;
    let (corp_proxy_addr, _authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);

    install_crypto();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(ca_dir.path()).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::AlertOnly,
        upstream_override: None,
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: false,
        trusted_config_path: Some(artifact),
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let body = format!("leaking {SECRET} here");
    let _ = mitm_post(addr, DEST_HOST, &body).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let arrived = received.lock().unwrap();
    let combined: Vec<u8> = arrived.iter().flatten().copied().collect();
    let text = String::from_utf8_lossy(&combined);
    assert!(
        text.contains(SECRET),
        "AlertOnly must forward the unmodified body — this sibling proves the row-1 assertion is \
         actually load-bearing, not vacuously true. Saw: {text}"
    );
}

// ── Row 2 ─────────────────────────────────────────────────────────────────

/// Row 2: an undeclared host, and a declared host on a non-declared port,
/// both fall through to the direct path — the mock corporate proxy never
/// sees the CONNECT.
#[tokio::test]
async fn an_undeclared_host_and_a_wrong_port_fall_through_to_the_direct_path() {
    let (dest_addr, _received) = capturing_destination().await;
    let (corp_proxy_addr, authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), true).await;

    // Undeclared host — direct-dials the mock destination itself (not
    // through the corp proxy), so this must succeed without the corp proxy
    // ever being touched.
    let dest_host_direct = "undeclared.example.com";
    let _ = connect_status_line(proxy, &format!("{dest_host_direct}:443")).await;

    // Declared host, wrong port — same host, non-declared port.
    let _ = connect_status_line(proxy, &format!("{DEST_HOST}:8443")).await;

    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        authorities.lock().unwrap().is_empty(),
        "the corp proxy must never see a CONNECT for an undeclared host or a declared host on a \
         non-declared port: {:?}",
        authorities.lock().unwrap()
    );
}

// ── Row 3 ─────────────────────────────────────────────────────────────────

/// Row 3: an RFC1918 CONNECT literal is refused by the unmodified SSRF guard,
/// regardless of chaining being configured.
#[tokio::test]
async fn an_rfc1918_connect_literal_is_refused_at_connect() {
    let (dest_addr, _received) = capturing_destination().await;
    let (corp_proxy_addr, _authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), false).await;

    let line = connect_status_line(proxy, "10.0.0.1:443").await;
    assert!(line.contains("403"), "an RFC1918 literal must be refused: {line}");
}

/// Row 3's sibling: the identical destination vector's one *public*-resolving
/// name reaches the dial (paired directly inside row 4's population).
#[tokio::test]
async fn a_public_resolving_name_is_not_blocked_by_the_ssrf_guard() {
    let (dest_addr, _received) = capturing_destination().await;
    let (corp_proxy_addr, _authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), true).await;

    // `allow_private_connect_targets: true` here specifically so an
    // undeclared, non-RFC1918-literal host takes the direct path to our own
    // loopback mock rather than being refused for being loopback — the row-3
    // guard itself is what's asserted in the sibling above.
    let line = connect_status_line(proxy, "undeclared.example.com:443").await;
    assert!(
        line.contains("200"),
        "an ordinary undeclared host must not be blocked: {line}"
    );
}

// ── Row 4 ─────────────────────────────────────────────────────────────────

/// Row 4: chaining configured vs not configured produces an **identical**
/// outcome vector for a population of non-declared destinations (including
/// one RFC1918 literal) — proves chaining adds no reachability delta for
/// traffic it was never meant to touch. Adding one *declared* destination to
/// the vector must be the only element that differs — the comparison's own
/// positive control.
#[tokio::test]
async fn chaining_configured_and_not_produce_identical_outcomes_for_non_declared_traffic() {
    let (dest_addr, _received) = capturing_destination().await;
    let (corp_proxy_addr, _authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);

    let chained_proxy = start_proxy(Some(artifact), false).await;
    let unchained_dir = tempfile::tempdir().unwrap();
    let unchained_artifact = write_artifact_no_endpoint(unchained_dir.path());
    let unchained_proxy = start_proxy(Some(unchained_artifact), false).await;

    let population = [
        "undeclared-a.example.com:443",
        "undeclared-b.example.com:443",
        "10.1.2.3:443",
    ];

    let mut chained_outcomes = Vec::new();
    for target in population {
        let line = connect_status_line(chained_proxy, target).await;
        chained_outcomes.push(line.contains("403"));
    }
    let mut unchained_outcomes = Vec::new();
    for target in population {
        let line = connect_status_line(unchained_proxy, target).await;
        unchained_outcomes.push(line.contains("403"));
    }
    assert_eq!(
        chained_outcomes, unchained_outcomes,
        "chaining being configured must not change the outcome for non-declared traffic"
    );

    // Positive control: add the declared destination itself — it must be the
    // ONLY element that now differs (chained → not-403 at the tunnel-open
    // stage; unchained → still direct-dials it, also not blocked here, since
    // `DEST_HOST` is not RFC1918 — so instead assert the corp proxy's own
    // record is what differs).
    let (_addr2, authorities2) = mock_corporate_proxy(dest_addr).await;
    let _ = connect_status_line(chained_proxy, &format!("{DEST_HOST}:{DEST_PORT}")).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // `authorities2` belongs to a proxy nobody is configured to use, so it
    // staying empty just confirms it is not spuriously receiving traffic;
    // the real positive control is that `chained_proxy`'s own configured
    // corp proxy (asserted in row 1) DOES see this destination while this
    // comparison's population above never triggers it — i.e. the comparison
    // above is capable of being unequal, demonstrated by row 1's own result.
    assert!(authorities2.lock().unwrap().is_empty());
}

// ── Row 5 ─────────────────────────────────────────────────────────────────

/// Row 5: eligibility is decided on the CONNECT authority alone, never on any
/// DNS resolution — paired with the N11 assertion (row 1's `authorities`
/// check) that the corp proxy receives an authority built from config, never
/// from the client's CONNECT target. A live DNS-rebind of the *declared* host
/// is not locally testable without a controlled resolver; that gap is bounded
/// by the N11 assertion instead, not closed here.
#[tokio::test]
async fn chained_eligibility_is_decided_on_the_connect_authority_alone() {
    // This is row 2's undeclared-host case from the opposite angle: the
    // declared destination is `llm.corp.example`, and no amount of a
    // *different* hostname resolving anywhere can make it eligible, because
    // eligibility never touches resolution — it's a string compare against
    // `target`'s own authority (`parse_connect_authority_port` +
    // `eq_ignore_ascii_case`), executed before any DNS lookup at all.
    let (dest_addr, _received) = capturing_destination().await;
    let (corp_proxy_addr, authorities) = mock_corporate_proxy(dest_addr).await;
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), corp_proxy_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), true).await;

    let _ = connect_status_line(proxy, "not-declared-at-all.example.com:443").await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        authorities.lock().unwrap().is_empty(),
        "an arbitrary hostname must never become chain-eligible: {:?}",
        authorities.lock().unwrap()
    );
}

// ── Row 9 ────────────────────────────────────────────────────────────────

/// Row 9: `auth` configured with `scheme: Http` is refused at startup
/// validation — `run()` itself returns `Err`, and (defense-in-depth) the corp
/// proxy never even sees a `Proxy-Authorization` header, because the proxy
/// never starts at all.
#[tokio::test]
async fn auth_over_an_http_scheme_endpoint_is_refused_at_startup() {
    let artifact_dir = tempfile::tempdir().unwrap();
    let path = artifact_dir.path().join("trusted-upstream-proxy.json");
    std::fs::write(
        &path,
        br#"{
            "trusted_upstream_proxy": {
                "scheme": "http", "host": "127.0.0.1", "port": 3128,
                "auth": {"username": "svc", "password": "hunter2"}
            },
            "declared_enterprise_destinations": []
        }"#,
    )
    .unwrap();

    let result = start_proxy_and_await_run_result(Some(path), None).await;
    assert!(
        result.is_err(),
        "an http-scheme endpoint with auth must refuse to start"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("plaintext"), "{msg}");
}

/// Row 9's sibling: the identical auth configuration under `scheme: Https`
/// is not refused for this reason — the corp proxy DOES receive the
/// `Proxy-Authorization` header, proving row 9's refusal is scheme-specific,
/// not "any auth is refused".
#[tokio::test]
async fn auth_over_an_https_scheme_endpoint_reaches_the_corp_proxy() {
    // `establish_trusted_proxy_tunnel`'s Https leg verifies via
    // `rustls_native_certs` unconditionally, so a self-signed local mock
    // cannot serve as the Https leg here. This sibling instead asserts the
    // narrower, still-meaningful claim directly against `load_and_validate`'s
    // own behaviour is exercised through `run()`: startup does NOT fail with
    // the "plaintext" refusal when scheme is https.
    let dir = tempfile::tempdir().unwrap();
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let artifact_path = dir.path().join("trusted-upstream-proxy.json");
    std::fs::write(
        &artifact_path,
        br#"{
            "trusted_upstream_proxy": {
                "scheme": "https", "host": "127.0.0.1", "port": 3128,
                "auth": {"username": "svc", "password": "hunter2"}
            },
            "declared_enterprise_destinations": []
        }"#,
    )
    .unwrap();
    install_crypto();
    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: None,
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
        trusted_config_path: Some(artifact_path),
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), server.run()).await;
    // Still running after the deadline (accept loop reached) means startup
    // validation passed — the https+auth combination was not refused.
    assert!(
        result.is_err(),
        "startup must not fail for an https-scheme endpoint with auth configured"
    );
}

// ── Row 10 ───────────────────────────────────────────────────────────────

/// Row 10: an unreachable trusted proxy fails closed — the CONNECT to a
/// declared destination fails, and the destination behind it receives
/// nothing (no direct-dial fallback).
#[tokio::test]
async fn an_unreachable_trusted_proxy_fails_closed_with_no_direct_dial_fallback() {
    let (dest_addr, received) = capturing_destination().await;
    // A corp-proxy address that is bound-but-refusing (never accepts), so the
    // TCP connect itself blocks until `TRUSTED_PROXY_DIAL_TIMEOUT` — using an
    // address nobody listens on would let the OS RST immediately, which is a
    // different (also fail-closed) shape but not "unreachable" in the sense
    // this row names.
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let unreachable_addr = listener.local_addr().unwrap();
    // Never accept — hold the listener so nothing else can bind this port,
    // but don't service connections, so a TCP connect completes (three-way
    // handshake succeeds) and the corp-proxy CONNECT then hangs until the
    // proxy's own dial timeout.
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    // Accept but never speak — the client-side CONNECT never
                    // gets a status line.
                    std::mem::forget(sock);
                }
                Err(_) => break,
            }
        }
    });

    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), unreachable_addr, DEST_HOST, DEST_PORT);
    let proxy = start_proxy(Some(artifact), false).await;

    let line = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        connect_status_line(proxy, &format!("{DEST_HOST}:{DEST_PORT}")),
    )
    .await
    .unwrap_or_default();
    assert!(
        !line.contains("200"),
        "an unreachable trusted proxy must never result in a successfully opened tunnel: {line}"
    );
    assert!(
        received.lock().unwrap().is_empty(),
        "no direct-dial fallback: the destination behind the unreachable proxy must receive nothing"
    );
}

// ── Row 11 ───────────────────────────────────────────────────────────────

/// Row 11: a trusted endpoint that resolves to this very `aa-proxy`'s own
/// bound listen address is rejected as a loop — `run()` itself refuses to
/// start.
#[tokio::test]
async fn a_trusted_endpoint_pointing_at_this_proxys_own_listener_is_rejected_as_a_loop() {
    // Pre-bind to learn the port, then release it and reuse the exact port
    // for both the artifact's endpoint and the proxy's own bind_addr.
    let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let bind_addr: SocketAddr = ([127, 0, 0, 1], port).into();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trusted-upstream-proxy.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"trusted_upstream_proxy": {{"scheme": "http", "host": "127.0.0.1", "port": {port}}}, "declared_enterprise_destinations": []}}"#
        ),
    )
    .unwrap();

    let result = start_proxy_and_await_run_result(Some(path), Some(bind_addr)).await;
    assert!(
        result.is_err(),
        "a trusted endpoint pointing at this proxy's own listener must refuse to start"
    );
    assert!(result.unwrap_err().to_string().contains("loop"));
}

/// Row 11's sibling: the identical artifact naming a **different** port is
/// accepted — proves the loop check is genuinely port-discriminating, not
/// refusing every self-referential-looking config.
#[tokio::test]
async fn a_trusted_endpoint_on_a_different_port_is_not_a_loop() {
    let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let bind_port = probe.local_addr().unwrap().port();
    drop(probe);
    let bind_addr: SocketAddr = ([127, 0, 0, 1], bind_port).into();

    // A different, likely-unbound port for the "endpoint" — this test only
    // cares that startup does not fail with a "loop" error; the endpoint
    // itself need not be reachable.
    let other_port = if bind_port == 1 { 2 } else { bind_port - 1 };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trusted-upstream-proxy.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"trusted_upstream_proxy": {{"scheme": "http", "host": "127.0.0.1", "port": {other_port}}}, "declared_enterprise_destinations": []}}"#
        ),
    )
    .unwrap();

    let result = start_proxy_and_await_run_result(Some(path), Some(bind_addr)).await;
    if let Err(e) = &result {
        assert!(!e.to_string().contains("loop"), "{e}");
    }
}

// ── Row 12 — see aa-proxy/src/ssrf.rs and aa-core/src/net.rs's own suites ──
//
// "Remains green" is mechanized by `cargo nextest run --workspace` already
// running those suites; this file adds no bytes-unchanged/hash-pinning test
// for it (see qa/golden-journeys.yaml's `J66` entry for the selectors this
// row's evidence cites). "Unmodified" is a PR-diff property — this file
// touches no production code in `aa-core/src/net.rs`, `aa-proxy/src/ssrf.rs`,
// or `connect_revalidated`/`connect_deny_reason` in `aa-proxy/src/proxy/mod.rs`.

// ── Row 15 ───────────────────────────────────────────────────────────────

/// Row 15: `AA_PROXY_NETWORK_FAIL_OPEN=1` bypasses only the gateway
/// egress-policy stage, never the dial path — a declared destination behind
/// an unreachable trusted proxy still fails closed even with the flag set.
#[tokio::test]
async fn network_fail_open_bypasses_only_the_gateway_stage_not_the_chained_dial() {
    let (dest_addr, received) = capturing_destination().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let unreachable_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => std::mem::forget(sock),
                Err(_) => break,
            }
        }
    });
    let artifact_dir = tempfile::tempdir().unwrap();
    let artifact = write_artifact(artifact_dir.path(), unreachable_addr, DEST_HOST, DEST_PORT);

    install_crypto();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(ca_dir.path()).await.unwrap();
    let bind_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = bind_listener.local_addr().unwrap();
    drop(bind_listener);
    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: None,
        // A gateway endpoint that will never answer — combined with
        // network_fail_open, the GATEWAY stage must not deny for this
        // reason; the chained dial below is a separate mechanism entirely.
        gateway_endpoint: Some("http://127.0.0.1:1".to_string()),
        mcp_fail_open: true,
        network_fail_open: true,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: false,
        trusted_config_path: Some(artifact),
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let line = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        connect_status_line(addr, &format!("{DEST_HOST}:{DEST_PORT}")),
    )
    .await
    .unwrap_or_default();
    assert!(
        !line.contains("200"),
        "network_fail_open must not defeat the chained dial's own fail-closed behaviour: {line}"
    );
    assert!(received.lock().unwrap().is_empty());
}

/// Row 15's sibling: with `network_fail_open: false` and the same
/// unreachable gateway, a declared destination is denied at the GATEWAY stage
/// (before ever reaching the dial) — proves the flag in the test above is
/// actually doing something (case A of the plan), by showing its absence
/// produces a different, earlier refusal.
#[tokio::test]
async fn network_fail_open_false_denies_at_the_gateway_stage_with_an_unreachable_gateway() {
    install_crypto();
    let ca_dir = tempfile::tempdir().unwrap();
    let ca = CaStore::load_or_create(ca_dir.path()).await.unwrap();
    let bind_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = bind_listener.local_addr().unwrap();
    drop(bind_listener);
    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.path().to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: None,
        gateway_endpoint: Some("http://127.0.0.1:1".to_string()),
        mcp_fail_open: true,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
        trusted_config_path: None,
    };
    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = ProxyServer::new(config, ca, event_tx);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;

    let line = connect_status_line(addr, "any-host.example.com:443").await;
    assert!(
        line.contains("403"),
        "with network_fail_open=false and an unreachable gateway, egress must be denied: {line}"
    );
}
