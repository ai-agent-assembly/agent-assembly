//! AAASM-6356 PR1 - end-to-end proof that, on a proxy with a gateway endpoint
//! configured, the response to *any* recognised MCP exchange (not only
//! `tools/call`) is withheld unless the real gateway allows it.
//!
//! Chain under test, nothing stubbed: scripted TLS upstream -> `aa-proxy` (MitM)
//! -> a real `aa_gateway::PolicyEngine` over a real gRPC socket (behind a
//! forwarder that can sever or silence it) -> a client inside the MitM tunnel.
//! Assertions are on the raw bytes the client receives.
//!
//! Every negative case is paired with a control that differs in exactly one
//! variable. Synthetic values only: `PATIENT-424242` matches the test policy's
//! operator pattern, which the proxy's built-in scanner cannot know.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::{AbortHandle, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use aa_core::{AgentId, AuditEntry};
use aa_gateway::alerts::SecretAlert;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::proxy::ProxyServer;
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tonic::transport::Server;

const MCP_HOSTNAME: &str = "mcp.example.com";
const PATIENT_ID: &str = "PATIENT-424242";

fn jsonrpc(method: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#)
}

fn text_result(text: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{text}"}}]}}}}"#)
}

const TOOL_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/file.txt"}}}"#;

fn policy(credential_action: &str) -> String {
    format!(
        r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm-6356-e2e-{credential_action}
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

fn install_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ── Raw HTTP builders ───────────────────────────────────────────────────────

fn json_response(status_line: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn ok_json(body: &str) -> Vec<u8> {
    json_response("200 OK", body)
}

/// A close-delimited event stream, as an SSE MCP server sends it.
fn sse_response(content_type: &str, events: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-cache\r\n\r\n{events}").into_bytes()
}

struct ClientRequest {
    method: &'static str,
    path: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: String,
}

impl ClientRequest {
    fn post(body: &str) -> Self {
        Self {
            method: "POST",
            path: "/mcp",
            headers: vec![("Content-Type", "application/json")],
            body: body.to_string(),
        }
    }

    fn get(headers: Vec<(&'static str, &'static str)>) -> Self {
        Self {
            method: "GET",
            path: "/mcp",
            headers,
            body: String::new(),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut head = format!("{} {} HTTP/1.1\r\nHost: {MCP_HOSTNAME}\r\n", self.method, self.path);
        for (k, v) in &self.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        if !self.body.is_empty() {
            head.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        head.push_str("\r\n");
        head.push_str(&self.body);
        head.into_bytes()
    }
}

// ── Upstream ────────────────────────────────────────────────────────────────

/// Called when the upstream has received the request, before it replies.
type OnRequest = Arc<dyn Fn() + Send + Sync>;

struct Upstream {
    addr: SocketAddr,
    request_count: Arc<Mutex<usize>>,
    _abort: AbortHandle,
}

impl Upstream {
    /// Replies to every request with exactly `response`, then closes.
    async fn start(ca: &CaStore, response: Vec<u8>, on_request: Option<OnRequest>) -> Self {
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
                let response = response.clone();
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
                        // Let the hook's effect land before the proxy sees the response.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    let _ = tls.write_all(&response).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
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

// ── Gateway (real engine + real gRPC), behind a forwarder that can go silent ─

struct Gateway {
    forwarder_addr: SocketAddr,
    /// While set, the forwarder swallows what the proxy sends and the gateway
    /// never answers: the connection stays up, the RPC hangs.
    silent: Arc<AtomicBool>,
    _forwarder: AbortHandle,
    _server: AbortHandle,
    alert_rx: Mutex<broadcast::Receiver<SecretAlert>>,
    audit: Arc<Mutex<Vec<AuditEntry>>>,
}

impl Gateway {
    async fn start(policy_yaml: &str) -> Self {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{policy_yaml}").unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
        let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).expect("policy must load"));
        let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
        let audit = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&audit);
        tokio::spawn(async move {
            while let Some(e) = audit_rx.recv().await {
                sink.lock().unwrap().push(e);
            }
        });
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
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            Server::builder()
                .add_service(PolicyServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .expect("gateway serve");
        });

        let silent = Arc::new(AtomicBool::new(false));
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forwarder_addr = front.local_addr().unwrap();
        let silent_flag = Arc::clone(&silent);
        let forwarder = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            loop {
                let Ok((inbound, _)) = front.accept().await else {
                    return;
                };
                let silent = Arc::clone(&silent_flag);
                conns.spawn(async move {
                    let Ok(outbound) = TcpStream::connect(real_addr).await else {
                        return;
                    };
                    let (mut in_r, mut in_w) = inbound.into_split();
                    let (mut out_r, mut out_w) = outbound.into_split();
                    let up = async move {
                        let mut buf = [0u8; 8192];
                        loop {
                            match in_r.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if !silent.load(Ordering::SeqCst) && out_w.write_all(&buf[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    };
                    let down = async move {
                        let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
                    };
                    tokio::join!(up, down);
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        Self {
            forwarder_addr,
            silent,
            _forwarder: forwarder.abort_handle(),
            _server: server.abort_handle(),
            alert_rx: Mutex::new(alert_rx),
            audit,
        }
    }

    fn drain_alerts(&self) -> Vec<SecretAlert> {
        let mut rx = self.alert_rx.lock().unwrap();
        let mut out = Vec::new();
        while let Ok(a) = rx.try_recv() {
            out.push(a);
        }
        out
    }

    fn go_silent_hook(&self) -> OnRequest {
        let flag = Arc::clone(&self.silent);
        Arc::new(move || flag.store(true, Ordering::SeqCst))
    }
}

// ── Proxy + client ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Endpoint {
    /// The live in-process gateway.
    Live,
    /// A configured endpoint nobody is listening on.
    Dead,
    /// No gateway configured: standalone mode.
    Unset,
}

struct ProxyOpts {
    endpoint: Endpoint,
    mcp_fail_open: bool,
    network_fail_open: bool,
    agent_id: Option<String>,
}

impl Default for ProxyOpts {
    fn default() -> Self {
        Self {
            endpoint: Endpoint::Live,
            mcp_fail_open: false,
            network_fail_open: false,
            agent_id: None,
        }
    }
}

async fn start_proxy(
    ca_dir: &Path,
    ca: CaStore,
    upstream: SocketAddr,
    gateway: SocketAddr,
    opts: &ProxyOpts,
    tx: broadcast::Sender<PipelineEvent>,
) -> (SocketAddr, AbortHandle) {
    let port = portpicker::pick_unused_port().expect("free port");
    let gateway_endpoint = match opts.endpoint {
        Endpoint::Live => Some(format!("http://{gateway}")),
        Endpoint::Dead => Some(format!(
            "http://127.0.0.1:{}",
            portpicker::pick_unused_port().expect("free port")
        )),
        Endpoint::Unset => None,
    };
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
        gateway_endpoint,
        mcp_fail_open: opts.mcp_fail_open,
        network_fail_open: opts.network_fail_open,
        agent_id: opts.agent_id.clone(),
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
    // The gateway connect completes just after the listener binds.
    tokio::time::sleep(Duration::from_millis(250)).await;
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

/// Everything the downstream client receives for one request, raw, read to EOF
/// (the proxy closes after every response) or to a 25s ceiling.
async fn send_through_proxy(proxy: SocketAddr, cfg: Arc<ClientConfig>, request: &ClientRequest) -> Vec<u8> {
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
    tls.write_all(&request.bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(25);
    while let Ok(Ok(n)) =
        tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), tls.read(&mut tmp)).await
    {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

struct Run {
    /// Exact bytes the client received.
    raw: Vec<u8>,
    seen: String,
    upstream_requests: usize,
    alerts: Vec<SecretAlert>,
    audit: Vec<AuditEntry>,
    elapsed: Duration,
}

struct Scenario {
    policy_action: &'static str,
    upstream_response: Vec<u8>,
    request: ClientRequest,
    proxy: ProxyOpts,
    /// The gateway stops answering once the upstream has the request.
    gateway_silent_after_request: bool,
}

impl Scenario {
    fn new(policy_action: &'static str, request: ClientRequest, upstream_response: Vec<u8>) -> Self {
        Self {
            policy_action,
            upstream_response,
            request,
            proxy: ProxyOpts::default(),
            gateway_silent_after_request: false,
        }
    }

    fn with_proxy(mut self, proxy: ProxyOpts) -> Self {
        self.proxy = proxy;
        self
    }

    async fn run(self) -> Run {
        install_crypto_provider();
        let dir = tempfile::TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let cfg = client_config(dir.path()).await;
        let gateway = Gateway::start(&policy(self.policy_action)).await;
        let hook = self.gateway_silent_after_request.then(|| gateway.go_silent_hook());
        let upstream = Upstream::start(&ca, self.upstream_response, hook).await;
        let (event_tx, _event_rx) = broadcast::channel::<PipelineEvent>(64);
        let (proxy, abort) = start_proxy(
            dir.path(),
            ca,
            upstream.addr,
            gateway.forwarder_addr,
            &self.proxy,
            event_tx,
        )
        .await;
        let started = Instant::now();
        let raw = send_through_proxy(proxy, cfg, &self.request).await;
        let elapsed = started.elapsed();
        // The gateway audits before it replies; this only lets the sink task drain.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let run = Run {
            seen: String::from_utf8_lossy(&raw).into_owned(),
            raw,
            upstream_requests: upstream.request_count(),
            alerts: gateway.drain_alerts(),
            audit: gateway.audit.lock().unwrap().clone(),
            elapsed,
        };
        abort.abort();
        run
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
        assert!(!r.seen.contains(s), "{s} reached the client: {}", r.seen);
    }
}

fn assert_forwarded(r: &Run, status: &str, must_contain: &str) {
    assert_eq!(r.upstream_requests, 1);
    assert!(
        r.seen.starts_with(&format!("HTTP/1.1 {status}")),
        "expected {status}, got: {}",
        r.seen
    );
    assert!(r.seen.contains(must_contain), "got: {}", r.seen);
}

/// `ToolResult` evaluations the gateway served for the exchange, by the
/// `tool_name` label the proxy sent (`action_type` 7).
fn tool_result_labels(r: &Run) -> Vec<String> {
    r.audit
        .iter()
        .filter_map(|e| serde_json::from_str::<serde_json::Value>(e.payload()).ok())
        .filter(|v| v["action_type"] == 7)
        .map(|v| v["action"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The id a `SecretAlert` carries for a proxy request with this `agent_id`.
fn alert_key(agent_id: &str) -> AgentId {
    AgentId::from_bytes(proto_agent_id_to_key(&ProtoAgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: agent_id.to_string(),
    }))
}

fn dirty() -> String {
    text_result(&format!("record {PATIENT_ID}"))
}

fn clean() -> String {
    text_result("nothing sensitive")
}

// ── Cases ───────────────────────────────────────────────────────────────────

/// (1) `resources/read` and `prompts/get` responses carrying an operator-pattern
/// value are withheld, and the gateway was asked under the method's label.
/// Control: the same exchange with a clean value is forwarded with its content.
#[tokio::test(flavor = "multi_thread")]
async fn non_tools_call_responses_are_gateway_evaluated_and_withheld() {
    for method in ["resources/read", "prompts/get"] {
        let label = format!("mcp-method:{method}");
        let r = Scenario::new("redact_only", ClientRequest::post(&jsonrpc(method)), ok_json(&dirty()))
            .run()
            .await;
        assert_withheld(&r, &[PATIENT_ID]);
        assert_eq!(tool_result_labels(&r), vec![label.clone()], "{method}");

        let control = Scenario::new("redact_only", ClientRequest::post(&jsonrpc(method)), ok_json(&clean()))
            .run()
            .await;
        assert_forwarded(&control, "200", "nothing sensitive");
        assert_eq!(tool_result_labels(&control), vec![label], "{method} control");
    }
}

/// (2) A batch of non-`tools/call` requests: the sensitive response is withheld,
/// the clean one forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn batch_response_is_gateway_evaluated() {
    let batch = format!("[{}]", jsonrpc("resources/read"));
    let r = Scenario::new(
        "redact_only",
        ClientRequest::post(&batch),
        ok_json(&format!("[{}]", dirty())),
    )
    .run()
    .await;
    assert_withheld(&r, &[PATIENT_ID]);
    assert_eq!(tool_result_labels(&r), vec!["mcp-method:batch".to_string()]);

    let control = Scenario::new(
        "redact_only",
        ClientRequest::post(&batch),
        ok_json(&format!("[{}]", clean())),
    )
    .run()
    .await;
    assert_forwarded(&control, "200", "nothing sensitive");
}

/// A request is MCP by its session/protocol header alone, whatever its body.
/// Control: the same GET without those headers is relayed untouched.
#[tokio::test(flavor = "multi_thread")]
async fn mcp_session_headers_make_a_bodyless_request_recognised() {
    for header in ["Mcp-Session-Id", "MCP-Protocol-Version"] {
        let r = Scenario::new(
            "redact_only",
            ClientRequest::get(vec![(header, "2025-06-18")]),
            ok_json(&dirty()),
        )
        .run()
        .await;
        assert_withheld(&r, &[PATIENT_ID]);
        assert_eq!(
            tool_result_labels(&r),
            vec!["mcp-method:unknown".to_string()],
            "{header}"
        );
    }
    let control = Scenario::new(
        "redact_only",
        ClientRequest::get(vec![("Accept", "application/json")]),
        ok_json(&dirty()),
    )
    .run()
    .await;
    assert_forwarded(&control, "200", PATIENT_ID);
    assert!(tool_result_labels(&control).is_empty());
}

/// (3) A gateway endpoint is configured but no client is live (start-up connect
/// failed under both fail-open knobs). Recognised responses are withheld - even a
/// clean `tools/call` result whose request was forwarded unevaluated - while an
/// empty `202` is forwarded. Control: with the endpoint unset, the same
/// `resources/read` response is forwarded unchanged, so "endpoint is set" is what
/// decides.
#[tokio::test(flavor = "multi_thread")]
async fn configured_endpoint_without_a_live_client_withholds_recognised_responses() {
    let dead = || ProxyOpts {
        endpoint: Endpoint::Dead,
        mcp_fail_open: true,
        network_fail_open: true,
        agent_id: None,
    };
    let r = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&clean()),
    )
    .with_proxy(dead())
    .run()
    .await;
    assert_withheld(&r, &["nothing sensitive"]);

    let r = Scenario::new("redact_only", ClientRequest::post(TOOL_CALL), ok_json(&clean()))
        .with_proxy(dead())
        .run()
        .await;
    assert_withheld(&r, &["nothing sensitive"]);

    let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let r = Scenario::new(
        "redact_only",
        ClientRequest::post(notification),
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .with_proxy(dead())
    .run()
    .await;
    assert_forwarded(&r, "202", "202 Accepted");

    let control = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&clean()),
    )
    .with_proxy(ProxyOpts {
        endpoint: Endpoint::Unset,
        mcp_fail_open: true,
        network_fail_open: true,
        agent_id: None,
    })
    .run()
    .await;
    assert_forwarded(&control, "200", "nothing sensitive");
}

/// With a live gateway an empty notification reply is forwarded and costs no
/// gateway call. Control: a non-empty reply to the same request is evaluated.
#[tokio::test(flavor = "multi_thread")]
async fn empty_notification_reply_is_forwarded_without_a_gateway_call() {
    let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let r = Scenario::new(
        "redact_only",
        ClientRequest::post(notification),
        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )
    .run()
    .await;
    assert_forwarded(&r, "202", "202 Accepted");
    assert!(tool_result_labels(&r).is_empty());

    let control = Scenario::new("redact_only", ClientRequest::post(notification), ok_json(&clean()))
        .run()
        .await;
    assert_forwarded(&control, "200", "nothing sensitive");
    assert_eq!(tool_result_labels(&control).len(), 1);
}

/// (4) Compatibility: a request that is not MCP gets its response relayed
/// byte-for-byte (original chunked framing and headers) with zero gateway
/// evaluations - even though the body holds a value the policy would withhold.
/// Controls differ in one variable: a JSON-RPC body (or an MCP session header)
/// on the request makes the same response a withheld, evaluated one.
#[tokio::test(flavor = "multi_thread")]
async fn non_mcp_exchange_on_an_enforcing_host_is_relayed_byte_identical() {
    let body = dirty();
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Custom: kept\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        body.len()
    )
    .into_bytes();

    let post = Scenario::new(
        "redact_only",
        ClientRequest::post(r#"{"name":"x","items":[1]}"#),
        chunked.clone(),
    )
    .run()
    .await;
    assert_eq!(post.raw, chunked, "POST response must be byte-identical");
    assert!(tool_result_labels(&post).is_empty());

    let get = Scenario::new(
        "redact_only",
        ClientRequest::get(vec![("Accept", "application/json")]),
        chunked.clone(),
    )
    .run()
    .await;
    assert_eq!(get.raw, chunked, "GET response must be byte-identical");
    assert!(tool_result_labels(&get).is_empty());

    let jsonrpc_post = Scenario::new("redact_only", ClientRequest::post(&jsonrpc("ping")), chunked.clone())
        .run()
        .await;
    assert_withheld(&jsonrpc_post, &[PATIENT_ID]);
    assert_eq!(tool_result_labels(&jsonrpc_post), vec!["mcp-method:ping".to_string()]);

    let session_get = Scenario::new(
        "redact_only",
        ClientRequest::get(vec![("Mcp-Session-Id", "s-1")]),
        chunked,
    )
    .run()
    .await;
    assert_withheld(&session_get, &[PATIENT_ID]);
    assert_eq!(tool_result_labels(&session_get).len(), 1);
}

/// (5, interim) An enforcing host serving `text/event-stream` is withheld before
/// any event byte - for a recognised POST and for a bodyless `GET` carrying
/// `Last-Event-ID`. Controls: with the endpoint unset the stream passes through
/// untouched; and the same recognised exchange answered as `application/json` is
/// evaluated and forwarded.
#[tokio::test(flavor = "multi_thread")]
async fn event_stream_response_on_an_enforcing_host_is_withheld() {
    let events = format!("id: 1\ndata: {}\n\n", dirty());
    let sse = sse_response("text/event-stream", &events);

    let post = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        sse.clone(),
    )
    .run()
    .await;
    assert_withheld(&post, &[PATIENT_ID, "id: 1", "data: "]);

    let get = Scenario::new(
        "redact_only",
        ClientRequest::get(vec![("Accept", "text/event-stream"), ("Last-Event-ID", "7")]),
        sse_response("Text/Event-Stream; charset=utf-8", &events),
    )
    .run()
    .await;
    assert_withheld(&get, &[PATIENT_ID]);

    let standalone = Scenario::new(
        "redact_only",
        ClientRequest::get(vec![("Accept", "text/event-stream"), ("Last-Event-ID", "7")]),
        sse.clone(),
    )
    .with_proxy(ProxyOpts {
        endpoint: Endpoint::Unset,
        ..ProxyOpts::default()
    })
    .run()
    .await;
    assert_eq!(standalone.raw, sse, "standalone proxy streams the bytes through");

    let as_json = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&clean()),
    )
    .run()
    .await;
    assert_forwarded(&as_json, "200", "nothing sensitive");
    assert_eq!(tool_result_labels(&as_json).len(), 1);
}

/// (6) Attribution and `alert_only`: the gateway raises one `SecretAlert` for a
/// non-`tools/call` response, attributed to the proxy's synthetic `aa-proxy`
/// identity even when the proxy is configured with another agent id, while the
/// content is delivered. Control: `redact_only` records it too but withholds.
#[tokio::test(flavor = "multi_thread")]
async fn alert_only_response_alert_is_attributed_to_the_proxy_identity() {
    let opts = || ProxyOpts {
        agent_id: Some("agent-x".to_string()),
        ..ProxyOpts::default()
    };
    let observed = Scenario::new(
        "alert_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&dirty()),
    )
    .with_proxy(opts())
    .run()
    .await;
    assert_forwarded(&observed, "200", PATIENT_ID);
    assert_eq!(observed.alerts.len(), 1, "got {:?}", observed.alerts);
    assert_eq!(observed.alerts[0].agent_id, alert_key("aa-proxy"));
    assert_ne!(observed.alerts[0].agent_id, alert_key("agent-x"));

    let enforced = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&dirty()),
    )
    .with_proxy(opts())
    .run()
    .await;
    assert_withheld(&enforced, &[PATIENT_ID]);
    assert_eq!(enforced.alerts.len(), 1);
}

/// (7) The gateway accepts the connection but never answers the response
/// evaluation: the response is withheld once `MCP_GATEWAY_RPC_TIMEOUT` (10 s)
/// elapses, not held forever. Control: the same exchange with a responsive gateway
/// is forwarded promptly.
#[tokio::test(flavor = "multi_thread")]
async fn hung_gateway_rpc_withholds_within_the_timeout() {
    let mut hung = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&clean()),
    );
    hung.gateway_silent_after_request = true;
    let r = hung.run().await;
    assert_withheld(&r, &["nothing sensitive"]);
    assert!(
        r.elapsed >= Duration::from_secs(9) && r.elapsed < Duration::from_secs(20),
        "expected a withhold at the ~10s RPC timeout, took {:?}",
        r.elapsed
    );

    let control = Scenario::new(
        "redact_only",
        ClientRequest::post(&jsonrpc("resources/read")),
        ok_json(&clean()),
    )
    .run()
    .await;
    assert_forwarded(&control, "200", "nothing sensitive");
    assert!(control.elapsed < Duration::from_secs(5), "took {:?}", control.elapsed);
}
