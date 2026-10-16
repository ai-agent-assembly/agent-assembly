//! AAASM-6355 - end-to-end proof that an MCP *response* is withheld unless the
//! real gateway allows it.
//!
//! Chain under test, nothing stubbed: TLS MCP upstream -> `aa-proxy` (MitM) ->
//! a real `aa_gateway::PolicyEngine` served over a real gRPC socket -> a client
//! inside the MitM TLS tunnel. Assertions are on the exact bytes the client
//! receives. `aa-proxy`'s own unit tests use a stub gateway; only a gateway
//! with operator `data.sensitive_patterns` can tell the proxy something its
//! built-in scanner cannot, so that is what these tests exercise.
//!
//! Every negative case is paired with a control that differs in exactly one
//! variable (the sensitive value, the policy action, the encoding, or whether
//! the gateway answers).
//!
//! Synthetic values only: `AKIAABCDEFGHIJKLMNOP` (fake AWS key shape) and
//! `PATIENT-424242` (matches the test policy's operator pattern).

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::{AbortHandle, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_core::AuditEntry;
use aa_gateway::alerts::SecretAlert;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tonic::transport::Server;

const MCP_HOSTNAME: &str = "mcp.example.com";
const FAKE_AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";
const PATIENT_ID: &str = "PATIENT-424242";
const TOOL_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/file.txt"}}}"#;

fn text_result(text: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{text}"}}]}}}}"#)
}

fn policy(credential_action: &str) -> String {
    format!(
        r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm-6355-e2e-{credential_action}
  version: "1.0.0"
spec:
  data:
    credential_action: {credential_action}
    sensitive_patterns:
      - "PATIENT-[0-9]{{6}}"
  tools:
    "*":
      allow: true
"#
    )
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

fn install_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Upstream ────────────────────────────────────────────────────────────────

/// Called when the upstream has received the request, before it replies. The
/// RPC-failure tests use it to kill the gateway *after* the request-side
/// `tools/call` has been allowed.
type OnRequest = Arc<dyn Fn() + Send + Sync>;

struct Upstream {
    addr: SocketAddr,
    request_count: Arc<Mutex<usize>>,
    _abort: AbortHandle,
}

impl Upstream {
    async fn start(ca: &CaStore, body: Vec<u8>, gzip_encoded: bool, on_request: Option<OnRequest>) -> Self {
        let ck = ca.sign_cert(MCP_HOSTNAME).expect("ca sign_cert");
        let cert = CertificateDer::from(ck.cert_der.clone());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(Mutex::new(0usize));
        let count = Arc::clone(&request_count);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let body = body.clone();
                let count = Arc::clone(&count);
                let on_request = on_request.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let head_end = loop {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p;
                        }
                    };
                    let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("").to_ascii_lowercase();
                    let cl: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse().ok()))
                        .unwrap_or(0);
                    while buf.len() < head_end + 4 + cl {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    *count.lock().unwrap() += 1;
                    if let Some(hook) = on_request {
                        hook();
                        // Let the abort land before the proxy sees the response.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    let encoding = if gzip_encoded { "Content-Encoding: gzip\r\n" } else { "" };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{encoding}Content-Length: {}\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&body).await;
                    let _ = tls.flush().await;
                });
            }
        });
        Self {
            addr,
            request_count,
            _abort: handle.abort_handle(),
        }
    }

    fn request_count(&self) -> usize {
        *self.request_count.lock().unwrap()
    }
}

// ── Gateway (real engine + real gRPC), behind a killable TCP forwarder ─────

struct Gateway {
    /// Address the proxy dials; aborting the forwarder severs every live
    /// connection and refuses new ones, i.e. a gateway outage.
    forwarder_addr: SocketAddr,
    forwarder: AbortHandle,
    _server: AbortHandle,
    /// Receives every `SecretAlert` the real `PolicyServiceImpl` publishes, the
    /// same hook `server::serve_tcp` attaches in production.
    alert_rx: Mutex<broadcast::Receiver<SecretAlert>>,
}

impl Gateway {
    async fn start(policy_yaml: &str) -> Self {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{policy_yaml}").unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
        let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).expect("policy must load"));
        let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
        let (secret_tx, alert_rx) = broadcast::channel::<SecretAlert>(64);
        let service = PolicyServiceImpl::with_registry(
            engine,
            Arc::new(AgentRegistry::new()),
            audit_tx,
            Arc::new(AtomicU64::new(0)),
            [0u8; 32],
        )
        .with_secret_alert_tx(secret_tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _keep_alive = _audit_rx;
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            Server::builder()
                .add_service(PolicyServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .expect("gateway serve");
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = front.local_addr().unwrap();
        let forwarder = tokio::spawn(async move {
            // Dropping the JoinSet when this task is aborted aborts every connection.
            let mut conns = JoinSet::new();
            loop {
                let Ok((mut inbound, _)) = front.accept().await else {
                    return;
                };
                conns.spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(real_addr).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        Self {
            forwarder_addr,
            forwarder: forwarder.abort_handle(),
            _server: server.abort_handle(),
            alert_rx: Mutex::new(alert_rx),
        }
    }

    /// Every alert published so far. The gateway publishes before it replies, so
    /// once the client has seen the proxy's answer the alert is already queued.
    fn drain_alerts(&self) -> Vec<SecretAlert> {
        let mut rx = self.alert_rx.lock().unwrap();
        let mut out = Vec::new();
        while let Ok(a) = rx.try_recv() {
            out.push(a);
        }
        out
    }

    fn killer(&self) -> OnRequest {
        let h = self.forwarder.clone();
        Arc::new(move || h.abort())
    }
}

// ── Proxy + client ──────────────────────────────────────────────────────────

async fn start_proxy(
    ca_dir: &Path,
    ca: CaStore,
    upstream: SocketAddr,
    gateway: SocketAddr,
    mcp_fail_open: bool,
    tx: broadcast::Sender<PipelineEvent>,
) -> (SocketAddr, AbortHandle) {
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
        credential_action: CredentialAction::default(),
        upstream_override: Some(upstream),
        gateway_endpoint: Some(format!("http://{gateway}")),
        mcp_fail_open,
        network_fail_open: false,
        agent_id: None,
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: false,
        trusted_config_path: None,
    };
    let bind_addr = config.bind_addr;
    let server = ProxyServer::new(config, ca, tx);
    let jh = tokio::spawn(async move { server.run().await.unwrap() });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(bind_addr).await.is_err() {
        assert!(tokio::time::Instant::now() < deadline, "proxy did not start");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Gateway connect completes just after the listener binds; without this
    // the first request can take the no-gateway fallback instead.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (bind_addr, jh.abort_handle())
}

async fn client_config(ca_dir: &Path) -> Arc<ClientConfig> {
    let pem = tokio::fs::read_to_string(ca_dir.join("ca-cert.pem")).await.unwrap();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der)).unwrap();
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Everything the downstream client received for one `tools/call`, raw.
async fn call_through_proxy(proxy: SocketAddr, cfg: Arc<ClientConfig>) -> Vec<u8> {
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    let target = format!("{MCP_HOSTNAME}:443");
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(tcp);
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    assert!(status.contains("200"), "CONNECT refused: {status}");
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).await.unwrap();
        if h.trim().is_empty() {
            break;
        }
    }
    let mut tls = TlsConnector::from(cfg)
        .connect(
            ServerName::try_from(MCP_HOSTNAME.to_string()).unwrap(),
            reader.into_inner(),
        )
        .await
        .expect("TLS to MitM");
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: {MCP_HOSTNAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{TOOL_CALL}",
        TOOL_CALL.len()
    );
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    // Read until EOF or the stream goes idle (a forwarded response may keep-alive).
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), tls.read(&mut tmp)).await {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

/// What the client actually sees: head + body text, gunzipping a gzip body.
fn visible(raw: &[u8]) -> String {
    use std::io::Read as _;
    let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return String::from_utf8_lossy(raw).into_owned();
    };
    let head = String::from_utf8_lossy(&raw[..p]).into_owned();
    let body = &raw[p + 4..];
    let text = if head.to_ascii_lowercase().contains("content-encoding: gzip") {
        let mut s = String::new();
        match flate2::read::GzDecoder::new(body).read_to_string(&mut s) {
            Ok(_) => s,
            Err(_) => String::from_utf8_lossy(body).into_owned(),
        }
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    format!("{head}\r\n\r\n{text}")
}

struct Run {
    seen: String,
    raw: Vec<u8>,
    upstream_requests: usize,
    alerts: Vec<SecretAlert>,
    /// Every audit/pipeline event the proxy broadcast for the call.
    events: Vec<PipelineEvent>,
}

/// Drive one call through the whole chain. `kill_gateway_on_request` severs the
/// gateway once the upstream has the (already-allowed) request.
async fn run(policy_action: &str, body: Vec<u8>, gzip_encoded: bool, fail_open: bool, kill_gateway: bool) -> Run {
    install_crypto_provider();
    let dir = tempfile::TempDir::new().unwrap();
    let ca = CaStore::load_or_create(dir.path()).await.unwrap();
    let cfg = client_config(dir.path()).await;
    let gateway = Gateway::start(&policy(policy_action)).await;
    let hook = kill_gateway.then(|| gateway.killer());
    let upstream = Upstream::start(&ca, body, gzip_encoded, hook).await;
    let (event_tx, mut event_rx) = broadcast::channel::<PipelineEvent>(64);
    let (proxy, abort) = start_proxy(
        dir.path(),
        ca,
        upstream.addr,
        gateway.forwarder_addr,
        fail_open,
        event_tx,
    )
    .await;
    let raw = call_through_proxy(proxy, cfg).await;
    let upstream_requests = upstream.request_count();
    let alerts = gateway.drain_alerts();
    let mut events = Vec::new();
    while let Ok(e) = event_rx.try_recv() {
        events.push(e);
    }
    abort.abort();
    Run {
        alerts,
        events,
        seen: visible(&raw),
        raw,
        upstream_requests,
    }
}

fn assert_withheld(r: &Run, secrets: &[&str]) {
    assert_eq!(r.upstream_requests, 1, "request must have reached the upstream");
    assert!(
        r.seen.starts_with("HTTP/1.1 502"),
        "expected withheld 502, got: {}",
        r.seen
    );
    assert!(r.seen.contains("withheld"), "got: {}", r.seen);
    for s in secrets {
        // Never print the synthetic value or the body that might contain it:
        // a failure message must not itself be a cleartext-logging sink.
        assert!(!r.seen.contains(s), "a withheld secret reached the client");
        assert!(!String::from_utf8_lossy(&r.raw).contains(s));
    }
}

fn assert_forwarded(r: &Run, must_contain: &str) {
    assert_eq!(r.upstream_requests, 1);
    assert!(r.seen.starts_with("HTTP/1.1 200"), "expected 200, got: {}", r.seen);
    assert!(r.seen.contains(must_contain), "got: {}", r.seen);
}

// ── Cases ───────────────────────────────────────────────────────────────────

/// (1) control for 2/3/5/6: a clean response is forwarded unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn clean_response_is_forwarded() {
    let r = run(
        "redact_only",
        text_result("nothing sensitive").into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_forwarded(&r, "nothing sensitive");
}

/// (2) operator-pattern value + `redact_only`: gateway answers Redact, which the
/// proxy cannot apply, so the response is withheld. Control: case 1.
#[tokio::test(flavor = "multi_thread")]
async fn operator_pattern_under_redact_only_is_withheld() {
    let r = run(
        "redact_only",
        text_result(&format!("id {PATIENT_ID}")).into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_withheld(&r, &[PATIENT_ID]);
}

/// (3) same value under `block`: gateway answers Deny, withheld. Control: the
/// same policy with a clean body.
#[tokio::test(flavor = "multi_thread")]
async fn operator_pattern_under_block_is_withheld() {
    let r = run(
        "block",
        text_result(&format!("id {PATIENT_ID}")).into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_withheld(&r, &[PATIENT_ID]);
    let control = run(
        "block",
        text_result("nothing sensitive").into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_forwarded(&control, "nothing sensitive");
}

/// (4) built-in secret only: the proxy redacts it itself and the gateway then
/// evaluates the already-redacted body. Observed behaviour is asserted.
#[tokio::test(flavor = "multi_thread")]
async fn builtin_secret_is_redacted_by_proxy_then_forwarded() {
    let r = run(
        "redact_only",
        text_result(&format!("key {FAKE_AWS_KEY} end")).into_bytes(),
        false,
        false,
        false,
    )
    .await;
    eprintln!("CASE4 observed: {}", r.seen);
    assert_eq!(r.upstream_requests, 1);
    assert!(
        !r.seen.contains(FAKE_AWS_KEY),
        "built-in secret reached the client: {}",
        r.seen
    );
    assert!(r.seen.starts_with("HTTP/1.1 200"), "got: {}", r.seen);
    assert!(r.seen.contains("[REDACTED:"), "got: {}", r.seen);
}

/// (5) built-in + operator value together: withheld, neither value present.
#[tokio::test(flavor = "multi_thread")]
async fn mixed_builtin_and_operator_values_are_withheld() {
    let body = text_result(&format!("key {FAKE_AWS_KEY} id {PATIENT_ID}"));
    let r = run("redact_only", body.into_bytes(), false, false, false).await;
    assert_withheld(&r, &[FAKE_AWS_KEY, PATIENT_ID]);
}

/// (6) gzip response: the proxy decodes it for evaluation, so an operator value
/// inside is withheld; the clean gzip control is forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn gzip_response_with_operator_value_is_withheld() {
    let dirty = gzip(text_result(&format!("id {PATIENT_ID}")).as_bytes());
    let r = run("redact_only", dirty, true, false, false).await;
    assert_withheld(&r, &[PATIENT_ID]);
}

#[tokio::test(flavor = "multi_thread")]
async fn gzip_clean_response_is_forwarded() {
    let clean = gzip(text_result("nothing sensitive").as_bytes());
    let r = run("redact_only", clean, true, false, false).await;
    assert_forwarded(&r, "nothing sensitive");
}

/// (7) the gateway dies after allowing the request: RPC failure on the response
/// is withheld whatever `mcp_fail_open` says. Control for each: gateway alive.
#[tokio::test(flavor = "multi_thread")]
async fn response_rpc_failure_is_withheld_with_fail_open_false() {
    let r = run(
        "redact_only",
        text_result("nothing sensitive").into_bytes(),
        false,
        false,
        true,
    )
    .await;
    assert_withheld(&r, &["nothing sensitive"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn response_rpc_failure_is_withheld_with_fail_open_true() {
    let r = run(
        "redact_only",
        text_result("nothing sensitive").into_bytes(),
        false,
        true,
        true,
    )
    .await;
    assert_withheld(&r, &["nothing sensitive"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn same_clean_response_is_forwarded_when_gateway_stays_up_with_fail_open_true() {
    let r = run(
        "redact_only",
        text_result("nothing sensitive").into_bytes(),
        false,
        true,
        false,
    )
    .await;
    assert_forwarded(&r, "nothing sensitive");
}

/// (8) `alert_only` is the operator's explicit "observe, don't enforce" choice:
/// the gateway allows (and raises an alert), so the value is forwarded. Pinned
/// so a change to that contract is a visible decision. Control: `redact_only`
/// (case 2) withholds the identical body.
#[tokio::test(flavor = "multi_thread")]
async fn alert_only_forwards_operator_pattern_value_by_design() {
    let r = run(
        "alert_only",
        text_result(&format!("id {PATIENT_ID}")).into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_forwarded(&r, PATIENT_ID);
}

/// The detection `alert_only` promises is a real record, not a silent allow: the
/// gateway publishes one `SecretAlert` for the response-direction match, while
/// the value still reaches the client. Controls: a clean body under the same
/// policy raises none, and `redact_only` records the same detection *and*
/// withholds. An alert carries kinds and a count only, never the matched value.
#[tokio::test(flavor = "multi_thread")]
async fn alert_only_records_a_secret_alert_for_the_response_detection() {
    let dirty = text_result(&format!("id {PATIENT_ID}")).into_bytes();

    let observed = run("alert_only", dirty.clone(), false, false, false).await;
    assert_forwarded(&observed, PATIENT_ID);
    assert_eq!(observed.alerts.len(), 1, "got {:?}", observed.alerts);
    let alert = &observed.alerts[0];
    eprintln!("ALERT_ONLY observed alert: {alert:?}");
    assert_eq!(alert.finding_count, 1);
    assert!(!alert.kinds.is_empty());
    assert!(
        !format!("{alert:?}").contains(PATIENT_ID),
        "the alert must not carry the matched value: {alert:?}"
    );

    let clean = run(
        "alert_only",
        text_result("nothing sensitive").into_bytes(),
        false,
        false,
        false,
    )
    .await;
    assert_forwarded(&clean, "nothing sensitive");
    assert!(clean.alerts.is_empty(), "clean body raised {:?}", clean.alerts);

    let enforced = run("redact_only", dirty, false, false, false).await;
    assert_withheld(&enforced, &[PATIENT_ID]);
    assert_eq!(enforced.alerts.len(), 1, "got {:?}", enforced.alerts);
    assert!(!format!("{:?}", enforced.alerts).contains(PATIENT_ID));
}

// ── Leak surface: envelope, tracing output, audit events ───────────────────

/// `tracing_subscriber` writer that appends into a shared buffer.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Text of every audit event, including the protobuf wire bytes: `Debug` prints
/// a `bytes` field as a list of integers, which would never contain a secret.
fn events_text(events: &[PipelineEvent]) -> String {
    use prost::Message as _;
    let mut out = String::new();
    for e in events {
        out.push_str(&format!("{e:?}\n"));
        if let PipelineEvent::Audit(enriched) = e {
            out.push_str(&String::from_utf8_lossy(&enriched.inner.encode_to_vec()));
            out.push('\n');
        }
    }
    out
}

/// Run one call with a thread-local tracing capture. Only a current-thread
/// runtime makes that capture complete: every task (upstream, gateway, proxy)
/// then logs on this thread, and the capture cannot see another test's output.
async fn run_captured(policy_action: &str, body: Vec<u8>, fail_open: bool, kill_gateway: bool) -> (Run, String) {
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let r = run(policy_action, body, false, fail_open, kill_gateway).await;
    (r, buf.text())
}

fn assert_no_leak(r: &Run, logs: &str, secrets: &[&str]) {
    // The capture is real, not vacuous: the proxy's withhold line and the
    // withheld audit event for this very call are present.
    assert!(logs.contains("read_file"), "tracing capture saw no tool name: {logs}");
    assert!(
        logs.contains("withholding response"),
        "tracing capture missed the withhold log line: {logs}"
    );
    let audit = events_text(&r.events);
    assert!(
        audit.contains("Violation(") && audit.contains("blocked_action: \"tools/call read_file\""),
        "no withheld (violation) audit event captured: {audit}"
    );
    for s in secrets {
        assert!(!logs.contains(s), "a secret leaked into tracing output");
        assert!(!audit.contains(s), "a secret leaked into an audit event");
        assert!(!r.seen.contains(s), "a secret leaked into the 502 envelope");
    }
}

#[tokio::test]
async fn withheld_response_does_not_leak_into_envelope_logs_or_audit_events() {
    let secrets = [PATIENT_ID, FAKE_AWS_KEY];
    let mixed = text_result(&format!("key {FAKE_AWS_KEY} id {PATIENT_ID}")).into_bytes();

    // Gateway answers Redact (unappliable) -> withheld.
    let (r, logs) = run_captured("redact_only", mixed.clone(), false, false).await;
    assert_withheld(&r, &secrets);
    assert_no_leak(&r, &logs, &secrets);

    // Gateway answers Deny -> withheld.
    let (r, logs) = run_captured("block", mixed.clone(), false, false).await;
    assert_withheld(&r, &secrets);
    assert_no_leak(&r, &logs, &secrets);

    // Gateway dies after allowing the request -> RPC failure, withheld even
    // with `mcp_fail_open`.
    let (r, logs) = run_captured("redact_only", mixed, true, true).await;
    assert_withheld(&r, &secrets);
    assert_no_leak(&r, &logs, &secrets);
}
