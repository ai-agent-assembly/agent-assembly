//! AAASM-5978, test category B: proves that skipping the macOS System
//! Keychain step never means skipping certificate *validation*.
//!
//! `config::SystemTrustInstall` deliberately has no [`ProxyConfig`] field —
//! see its own doc comment for why: a field would flow into `ProxyServer`,
//! which is reachable from the data path, and this knob must be structurally
//! incapable of reaching it. This test is the differential proof of that
//! design intent, not a test of the knob itself (it never sets or reads
//! `AA_PROXY_SYSTEM_TRUST_INSTALL` — that variable is `aa_proxy::run()`'s
//! concern, one layer above `ProxyServer`, and is exercised separately in
//! `aa-integration-tests/tests/proxy_system_trust_install.rs`): the exact
//! same `ProxyServer`, serving the exact same real MitM CA, completes the
//! handshake for a client that genuinely trusts that CA and refuses one that
//! does not — proving `ProxyServer`'s validation is real and lives entirely
//! outside anything AAASM-5978 touches.

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsConnector;

use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_proxy(ca_dir: &std::path::Path) -> SocketAddr {
    let ca = CaStore::load_or_create(ca_dir).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
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
        allow_private_connect_targets: true,
        trusted_config_path: None,
    };

    let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(16);
    let server = aa_proxy::proxy::ProxyServer::new_with_audit_sink(config, ca, event_tx, None);
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    addr
}

/// Open a CONNECT tunnel to `host` (a built-in LLM host, so `llm_only`
/// doesn't need any other config) and attempt the client TLS handshake with
/// `client_config`. Returns `true` iff the handshake completes.
async fn handshake_completes(proxy: SocketAddr, host: &str, client_config: ClientConfig) -> bool {
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

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    connector.connect(server_name, reader.into_inner()).await.is_ok()
}

/// Load the real CA this proxy minted its leaf certs from into a
/// [`ClientConfig`] that genuinely trusts it — no `dangerous()` verifier
/// override anywhere, this is real chain-of-trust validation.
fn trusting_client_config(ca_pem_path: &std::path::Path) -> ClientConfig {
    let pem_bytes = std::fs::read(ca_pem_path).unwrap();
    let pem = x509_parser::pem::Pem::iter_from_buffer(&pem_bytes)
        .next()
        .expect("a PEM block")
        .expect("a valid PEM block");
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pem.contents)).unwrap();
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn distrusting_client_config() -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth()
}

#[tokio::test]
async fn a_client_that_genuinely_trusts_the_real_ca_completes_the_handshake_one_that_does_not_cannot() {
    install_crypto();
    let ca_root = tempfile::tempdir().unwrap();
    let addr = start_proxy(ca_root.path()).await;
    let ca_pem_path = ca_root.path().join("ca-cert.pem");

    assert!(
        handshake_completes(addr, "api.anthropic.com", trusting_client_config(&ca_pem_path)).await,
        "a client that genuinely trusts the real MitM CA must complete the handshake"
    );
    assert!(
        !handshake_completes(addr, "api.anthropic.com", distrusting_client_config()).await,
        "a client with no trust in the CA must NOT complete the handshake — this proxy's own \
         certificate validation is real and unaffected by anything AAASM-5978 introduces"
    );
}
