//! AAASM-5871 E2E — a real out-of-process `aa-proxy` REDACT event reaches the
//! real Scrub/Alerts dashboard API via the production telemetry hop.
//!
//! This is the full-stack counterpart to the `aa-api/tests/redaction_telemetry.rs`
//! integration test (which drives the ingest with a synthetic gRPC client). Here
//! nothing is faked: a live `aa_proxy::proxy::ProxyServer` MitM-terminates a real
//! HTTPS request carrying a synthetic AWS key, redacts it before forwarding, and
//! — configured via `AA_PROXY_TELEMETRY_ENDPOINT` exactly as in production —
//! reports the `ForwardedRedacted` decision over gRPC to `aa-api`'s
//! `RedactionTelemetryService`. The event flows through the shipped
//! capture → alert store → `GET /api/v1/alerts` path served by a live axum
//! server.
//!
//! Proves the four AAASM-5871 E2E requirements:
//!   1. a real aa-proxy REDACT event reaches the backend;
//!   2. the dashboard/API observes the corresponding real event;
//!   3. no raw secret is persisted or transported;
//!   4. existing enforcement behavior does not regress (the forwarded upstream
//!      bytes are redacted, and the raw key never reaches upstream).
//!
//! Single test by design: it sets the process-global `AA_PROXY_TELEMETRY_ENDPOINT`
//! env var, so it owns this test binary to stay deterministic.
//!
//! Synthetic secret only — `AKIAIOSFODNN7EXAMPLE` is from AWS public docs.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;

use common::TopologyTestEnv;

/// AWS access key ID from AWS public documentation. Synthetic — never live.
const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// LLM hostname the client CONNECTs to; `detect_api` classifies it as OpenAI,
/// triggering the proxy's body-inspection + redaction branch.
const LLM_HOSTNAME: &str = "api.openai.com";

/// Install rustls's default crypto provider exactly once per process.
fn install_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// In-process TLS-terminating HTTP upstream that records inbound request bodies
/// and replies with a canned chat-completion envelope. Lets us assert what the
/// proxy actually forwarded upstream (the enforcement invariant).
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
                    let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                    let cl: usize = head
                        .lines()
                        .find_map(|line| {
                            let lower = line.to_ascii_lowercase();
                            lower.strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    let body_start = head_end + 4;
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

/// Build a [`ClientConfig`] that trusts the proxy's per-host CA.
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
    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

/// Spin up a `ProxyServer` with `RedactOnly` credential action pointed at the
/// loopback capture upstream, returning its bound address and abort handle.
async fn start_proxy(
    ca_dir: &std::path::Path,
    ca: CaStore,
    upstream_override: SocketAddr,
) -> (SocketAddr, broadcast::Receiver<PipelineEvent>, tokio::task::AbortHandle) {
    let port = portpicker::pick_unused_port().expect("free port");
    let config = ProxyConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 10,
        llm_only: false,
        mitm_hosts: Vec::new(),
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::RedactOnly,
        upstream_override: Some(upstream_override),
        gateway_endpoint: None,
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: false,
    };
    let bind_addr = config.bind_addr;
    let (tx, rx) = broadcast::channel(64);
    let server = ProxyServer::new(config, ca, tx);
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

/// Drive one HTTPS request carrying `body` through the proxy to `LLM_HOSTNAME`.
async fn send_through_proxy(proxy_addr: SocketAddr, client_config: Arc<ClientConfig>, body: &str) -> String {
    let tcp = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
    let target = format!("{LLM_HOSTNAME}:443");
    let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    let mut tcp = tcp;
    tcp.write_all(connect.as_bytes()).await.expect("write CONNECT");

    let mut reader = BufReader::new(tcp);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.expect("read connect status");
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await.expect("read header line");
        if h.trim().is_empty() {
            break;
        }
    }
    assert!(
        status_line.contains("200"),
        "CONNECT must succeed for redact_only, got: {status_line}"
    );

    let server_name = ServerName::try_from(LLM_HOSTNAME.to_string()).expect("server name");
    let connector = TlsConnector::from(client_config);
    let tcp = reader.into_inner();
    let mut tls = connector.connect(server_name, tcp).await.expect("tls connect");

    let req = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {LLM_HOSTNAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    tls.write_all(req.as_bytes()).await.expect("write inner request");
    let mut response_buf = vec![0u8; 1024];
    let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut response_buf)).await;
    status_line
}

#[tokio::test(flavor = "multi_thread")]
async fn real_proxy_redaction_reaches_dashboard_api() {
    install_crypto_provider();

    // ── Backend: real API server + the shipped secret-alert capture pipeline ──
    let env = TopologyTestEnv::start().await.expect("api harness");
    let store: Arc<dyn aa_api::alerts::AlertStore> = env.alert_store.clone();
    let _capture = aa_api::alerts::capture::spawn_secret_alert_capture(env.events.subscribe_secret(), store);

    // ── Telemetry ingest: real RedactionTelemetryService over the API's sender ─
    let telemetry_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let telemetry_addr = telemetry_listener.local_addr().unwrap();
    let secret_tx = env.events.secret_sender();
    tokio::spawn(async move {
        aa_api::server::serve_telemetry_grpc(telemetry_listener, secret_tx, std::future::pending::<()>())
            .await
            .unwrap();
    });

    // Configure the proxy exactly as production does — via the env var it reads
    // at startup. This binary owns the process env (single test).
    std::env::set_var("AA_PROXY_TELEMETRY_ENDPOINT", format!("http://{telemetry_addr}"));

    // ── Proxy: a real MitM ProxyServer forwarding to a capture upstream ───────
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = Arc::new(client_trust_proxy_ca(dir.path()).await);
    let upstream = TlsCapturingUpstream::start(&ca).await;
    let (proxy_addr, _rx, abort) = start_proxy(dir.path(), ca, upstream.addr).await;

    // ── Act: send a synthetic AWS key through the proxy ───────────────────────
    let body = format!(r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"my key is {FAKE_AWS_ACCESS_KEY}"}}]}}"#);
    send_through_proxy(proxy_addr, client_config, &body).await;

    // ── Assert (4): enforcement did not regress — the forwarded bytes are
    //     redacted and the raw key never reached upstream ───────────────────────
    for _ in 0..50 {
        if upstream.request_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(upstream.request_count(), 1, "upstream must receive exactly one forwarded request");
    let forwarded = upstream.last_body().expect("upstream captured body");
    assert!(
        forwarded.contains("[REDACTED:AwsAccessKey]"),
        "forwarded body must carry the [REDACTED:AwsAccessKey] marker; got: {forwarded}",
    );
    assert!(
        !forwarded.contains(FAKE_AWS_ACCESS_KEY),
        "SECURITY INVARIANT: raw AWS key reached upstream — got: {forwarded}",
    );

    // ── Assert (1) + (2): the real REDACT event reached the backend and the
    //     dashboard API observes it. Poll the live HTTP server. ─────────────────
    let alerts_url = format!("http://{}/api/v1/alerts", env.addr);
    let http = reqwest::Client::new();
    let mut observed: Option<serde_json::Value> = None;
    for _ in 0..100 {
        let resp = http.get(&alerts_url).send().await.expect("GET /api/v1/alerts");
        let json: serde_json::Value = resp.json().await.expect("alerts json");
        if json["total"].as_u64().unwrap_or(0) >= 1 {
            observed = Some(json);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let json = observed.expect("a secret alert must surface on /api/v1/alerts within the timeout");

    let items = json["items"].as_array().expect("items array");
    let secret = items
        .iter()
        .find(|a| a["category"] == "secret_detected")
        .expect("a secret_detected alert must be present");
    assert_eq!(secret["severity"], "critical");
    assert_eq!(secret["detected_pattern_type"], "AwsAccessKey");
    assert_eq!(secret["redacted_value"], "[REDACTED:AwsAccessKey]");

    // ── Assert (3): no raw secret is persisted or transported ─────────────────
    let raw = serde_json::to_string(&json).expect("serialize alerts json");
    assert!(
        !raw.contains(FAKE_AWS_ACCESS_KEY),
        "SECURITY INVARIANT: raw AWS key must never appear in the dashboard API response; body was: {raw}",
    );

    abort.abort();
    std::env::remove_var("AA_PROXY_TELEMETRY_ENDPOINT");
}
