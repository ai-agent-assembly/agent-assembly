//! Integration tests for the aa-proxy TCP accept loop and CONNECT handling.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use tokio::sync::broadcast;

use aa_proxy::config::{CredentialAction, ProxyConfig};
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
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: false,
        credential_action: CredentialAction::default(),
        upstream_override: None,
        gateway_endpoint: None,
        mcp_fail_open: false,
        // Integration tests dial loopback mock upstreams over both the CONNECT
        // and the plain-HTTP forward paths. The plain-HTTP path now re-validates
        // resolved IPs against the SSRF denylist (AAASM-3140), which blocks
        // loopback — so the test-only escape hatch must be enabled here, exactly
        // as the CONNECT/tunnel paths already require for their loopback mocks.
        // Production `from_env` keeps this false.
        allow_private_connect_targets: true,
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

/// AAASM-3588: adversarial attacker tests turning the Story's three acceptance
/// criteria into executable, regression-proof checks against the real proxy
/// data path (CONNECT → TLS MitM → in-tunnel HTTP → upstream dial).
mod attacker {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::broadcast;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use aa_proxy::config::{CredentialAction, ProxyConfig};
    use aa_proxy::credentials::CredentialStore;
    use aa_proxy::proxy::http::read_http_request;
    use aa_proxy::tls::CaStore;
    use aa_runtime::pipeline::PipelineEvent;

    const REAL_KEY: &str = "sk-REAL-PROVIDER-KEY-do-not-leak";
    const ALLOWED_HOST: &str = "api.openai.com";
    const EVIL_HOST: &str = "evil.attacker.com";

    /// A TLS `ServerCertVerifier` that accepts any cert — the test client trusts
    /// whatever the proxy's MitM presents (cert validity is not under test here).
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

    /// What a single upstream request observed, shared back to the test.
    #[derive(Default)]
    struct UpstreamLog {
        authorization: Option<String>,
        saw_request: bool,
    }

    /// Start a TLS mock upstream on loopback. Records the inbound request's
    /// Authorization header, returns a fixed JSON body, and reports its address.
    async fn start_tls_upstream(body: &'static str) -> (SocketAddr, Arc<Mutex<UpstreamLog>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Mutex::new(UpstreamLog::default()));
        let log_task = Arc::clone(&log);

        // Self-signed leaf for the upstream; the proxy dials it with
        // skip_upstream_tls_verify so the cert is accepted.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let log = Arc::clone(&log_task);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else { return };
                    let mut reader = BufReader::new(tls);
                    if let Ok(Some(req)) = read_http_request(&mut reader).await {
                        let mut g = log.lock().unwrap();
                        g.saw_request = true;
                        g.authorization = req.header("authorization").map(|s| s.to_string());
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let mut tls = reader.into_inner();
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (addr, log)
    }

    /// Build a proxy config whose upstream dial is redirected to `upstream`,
    /// with `allowlist` enforced and the given provider credentials injected.
    fn proxy_config(ca_dir: &std::path::Path, upstream: SocketAddr, allowlist: Vec<String>) -> ProxyConfig {
        ProxyConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            ca_dir: ca_dir.to_path_buf(),
            cert_cache_capacity: 10,
            llm_only: false,
            denied_hosts: Vec::new(),
            network_allowlist: allowlist,
            // Accept the mock upstream's self-signed cert.
            skip_upstream_tls_verify: true,
            credential_action: CredentialAction::AlertOnly,
            upstream_override: Some(upstream),
            gateway_endpoint: None,
            mcp_fail_open: false,
            allow_private_connect_targets: true,
        }
    }

    async fn start_proxy_with_creds(
        config: ProxyConfig,
        ca: CaStore,
        creds: CredentialStore,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(config.bind_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cfg = ProxyConfig {
            bind_addr: addr,
            ..config
        };
        let (tx, _rx) = broadcast::channel::<PipelineEvent>(16);
        let server = aa_proxy::proxy::ProxyServer::new(cfg, ca, tx).with_credentials(creds);
        let handle = tokio::spawn(async move {
            let _ = server.run().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, handle)
    }

    /// Open a CONNECT tunnel through the proxy for `connect_host`, complete the
    /// TLS MitM handshake (SNI = `sni_host`), send `request`, and return the raw
    /// client-visible response bytes.
    async fn mitm_roundtrip(proxy: SocketAddr, connect_host: &str, sni_host: &str, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let connect = format!("CONNECT {connect_host}:443 HTTP/1.1\r\nHost: {connect_host}:443\r\n\r\n");
        stream.write_all(connect.as_bytes()).await.unwrap();

        // Read the "200 Connection Established" line + blank line.
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        use tokio::io::AsyncBufReadExt;
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("200"), "tunnel not established: {line}");
        loop {
            let mut hl = String::new();
            reader.read_line(&mut hl).await.unwrap();
            if hl.trim().is_empty() {
                break;
            }
        }
        let stream = reader.into_inner();

        // TLS handshake as the agent would, against the proxy's MitM cert.
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from(sni_host.to_string()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();

        tls.write_all(request).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut out)).await;
        out
    }

    #[tokio::test]
    async fn credential_heist_agent_never_sees_real_key_and_upstream_gets_injected() {
        // AC1: an agent request with a bogus Authorization reaches the mock
        // upstream carrying the INJECTED real key (agent's own header stripped),
        // and the real key never appears in the client-visible response bytes.
        install_crypto();
        let dir = tempfile::TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let (upstream, log) = start_tls_upstream("{\"ok\":true}").await;
        let config = proxy_config(dir.path(), upstream, vec![ALLOWED_HOST.to_string()]);
        let creds = CredentialStore::from_pairs([(ALLOWED_HOST.to_string(), REAL_KEY.as_bytes().to_vec())]);
        let (proxy, _h) = start_proxy_with_creds(config, ca, creds).await;

        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {ALLOWED_HOST}\r\n\
             Authorization: Bearer agent-bogus\r\nContent-Length: 2\r\n\r\nhi"
        );
        let response = mitm_roundtrip(proxy, ALLOWED_HOST, ALLOWED_HOST, req.as_bytes()).await;

        // (a) upstream received the injected real key, not the agent's.
        let g = log.lock().unwrap();
        assert!(g.saw_request, "upstream never received the request");
        assert_eq!(
            g.authorization.as_deref(),
            Some(&format!("Bearer {REAL_KEY}")[..]),
            "upstream must receive the injected real provider key"
        );

        // (b) the real key never appears in the client-visible response stream.
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            !response_str.contains(REAL_KEY),
            "real provider key leaked back to the agent: {response_str}"
        );
        assert!(
            response_str.contains("200"),
            "expected a 200 relayed to the agent: {response_str}"
        );
    }

    #[tokio::test]
    async fn forged_in_tunnel_host_is_rejected_and_evil_host_never_dialed() {
        // AC2: CONNECT an allowlisted host, then forge `Host: evil.attacker.com`
        // inside the tunnel. The proxy must reject with 403 and never dial the
        // evil host (upstream_override points at the mock, which must see no
        // request because the deny happens before any dial).
        install_crypto();
        let dir = tempfile::TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let (upstream, log) = start_tls_upstream("{\"ok\":true}").await;
        let config = proxy_config(dir.path(), upstream, vec![ALLOWED_HOST.to_string()]);
        let creds = CredentialStore::from_pairs([(ALLOWED_HOST.to_string(), REAL_KEY.as_bytes().to_vec())]);
        let (proxy, _h) = start_proxy_with_creds(config, ca, creds).await;

        let req = format!("POST /v1/chat/completions HTTP/1.1\r\nHost: {EVIL_HOST}\r\nContent-Length: 2\r\n\r\nhi");
        // CONNECT to the allowlisted host (tunnel opens) but forge the inner Host.
        let response = mitm_roundtrip(proxy, ALLOWED_HOST, ALLOWED_HOST, req.as_bytes()).await;

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.contains("403"),
            "forged in-tunnel host must be rejected with 403, got: {response_str}"
        );
        // Give any (erroneous) dial a moment, then assert the upstream saw nothing.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !log.lock().unwrap().saw_request,
            "evil host must never be dialed when the in-tunnel host is rejected"
        );
    }

    #[tokio::test]
    async fn proxy_never_echoes_configured_key_to_the_client() {
        // AC3 (framing): even on a normal allowed request, the proxy must never
        // emit its configured provider key into any client-visible byte stream.
        install_crypto();
        let dir = tempfile::TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        // Upstream deliberately echoes a benign body; the key must not appear.
        let (upstream, _log) = start_tls_upstream("{\"choices\":[]}").await;
        let config = proxy_config(dir.path(), upstream, vec![ALLOWED_HOST.to_string()]);
        let creds = CredentialStore::from_pairs([(ALLOWED_HOST.to_string(), REAL_KEY.as_bytes().to_vec())]);
        let (proxy, _h) = start_proxy_with_creds(config, ca, creds).await;

        let req = format!("POST /v1/x HTTP/1.1\r\nHost: {ALLOWED_HOST}\r\nContent-Length: 2\r\n\r\nhi");
        let response = mitm_roundtrip(proxy, ALLOWED_HOST, ALLOWED_HOST, req.as_bytes()).await;

        let response_str = String::from_utf8_lossy(&response);
        assert!(
            !response_str.contains(REAL_KEY),
            "proxy echoed its configured provider key to the client: {response_str}"
        );
    }
}
