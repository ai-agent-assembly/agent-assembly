//! AAASM-6261 (J83) AC2: what the proxy tells the gateway about who is behind a
//! connection, measured against a real second OS process.
//!
//! Two different properties are kept apart here, and the tests are named for the
//! one they measure:
//!
//! * **proxy identity**: this proxy instance is bound to agent X by a
//!   gateway-validated launch authorization. No such authorization exists yet, so
//!   the proxy sends a blank identity and the gateway records it as unattributed.
//! * **connection origin**: the process opening a connection is the governed
//!   agent. The proxy has no mechanism for this (no `Proxy-Authorization`, no
//!   peer-PID lookup), so a second process of the same user is indistinguishable
//!   from the agent. The test below *measures* that, rather than arguing it.
//!
//! The stub gateway records exactly what each `CheckAction` claimed, so an
//! attribution can only appear in these results if the proxy sent one.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_proxy::audit_jsonl::ProxyAuditEntry;
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

const HOST: &str = "hooks.example.com";
/// A label the launch carries. It must never reach the gateway.
const LABEL_A: &str = "label-of-launch-a";
const LABEL_B: &str = "label-of-launch-b";

/// What one network `CheckAction` claimed: `(agent_id, credential_token)`.
type Claim = (String, String);

/// A gateway stand-in that records every network claim and allows it.
struct StubGateway {
    seen: Arc<Mutex<Vec<Claim>>>,
}

#[tonic::async_trait]
impl PolicyService for StubGateway {
    async fn check_action(&self, req: Request<CheckActionRequest>) -> Result<Response<CheckActionResponse>, Status> {
        let request = req.get_ref();
        if matches!(
            request.context.as_ref().and_then(|c| c.action.as_ref()),
            Some(Action::NetworkCall(_))
        ) {
            let agent = request
                .agent_id
                .as_ref()
                .map(|a| a.agent_id.clone())
                .unwrap_or_default();
            self.seen
                .lock()
                .unwrap()
                .push((agent, request.credential_token.clone()));
        }
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

async fn spawn_gateway() -> (String, Arc<Mutex<Vec<Claim>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = StubGateway {
        seen: Arc::clone(&seen),
    };
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve(addr)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    (format!("http://{addr}"), seen)
}

async fn start_proxy(
    gateway: &str,
    label: Option<&str>,
    ca_dir: &std::path::Path,
) -> (SocketAddr, mpsc::Receiver<ProxyAuditEntry>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = CaStore::load_or_create(ca_dir).await.unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let config = ProxyConfig {
        bind_addr: addr,
        ca_dir: ca_dir.to_path_buf(),
        cert_cache_capacity: 8,
        llm_only: true,
        mitm_hosts: vec![HOST.to_string()],
        denied_hosts: Vec::new(),
        network_allowlist: Vec::new(),
        skip_upstream_tls_verify: true,
        credential_action: CredentialAction::AlertOnly,
        upstream_override: None,
        gateway_endpoint: Some(gateway.to_string()),
        mcp_fail_open: false,
        network_fail_open: false,
        agent_id: label.map(str::to_string),
        ready_file: None,
        parent_pid: None,
        allow_private_connect_targets: true,
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

/// Send a CONNECT and return the status line the proxy answered with.
async fn connect_status(proxy: SocketAddr) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let connect = format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line
}

/// The same CONNECT, opened by a **separate OS process** (`bash` with its own
/// `/dev/tcp`) that holds no secret and no label: the stand-in for any other
/// process of the same user that can reach the proxy's loopback port.
async fn connect_status_from_another_process(proxy: SocketAddr) -> String {
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{port}; printf 'CONNECT {HOST}:443 HTTP/1.1\\r\\nHost: {HOST}:443\\r\\n\\r\\n' >&3; head -n 1 <&3",
        port = proxy.port()
    );
    let out = tokio::process::Command::new("bash")
        .args(["-c", &script])
        .output()
        .await
        .expect("spawn a second process");
    assert_ne!(out.stdout.len(), 0, "the second process got no answer: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Neither launch's label reaches the gateway, so two launches are not told apart
/// by it and neither is named. This pins the removal of the asserted-label
/// attribution: a proxy that sent its label would be recorded under it.
#[tokio::test]
async fn a_launch_label_is_never_sent_to_the_gateway() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway().await;
    let (proxy_a, _audit_a) = start_proxy(&gateway, Some(LABEL_A), dir_a.path()).await;
    let (proxy_b, _audit_b) = start_proxy(&gateway, Some(LABEL_B), dir_b.path()).await;

    assert!(connect_status(proxy_a).await.contains("200"));
    assert!(connect_status(proxy_b).await.contains("200"));
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(String::new(), String::new()), (String::new(), String::new())],
        "the gateway must be told nothing about who either proxy serves"
    );
}

/// MEASURED: connection origin is **not** verified. A second process of the same
/// user that reaches launch A's proxy produces the same gateway claim as launch
/// A's own connection, because the proxy sends no identity for either. The
/// property that holds is the narrower one: the second process is **not
/// attributed to agent A** (nobody is named), so it cannot borrow A's identity at
/// the gateway. It can still use A's proxy, and A's proxy-local audit record
/// carries A's label for it, which is an assertion and not attribution.
#[tokio::test]
async fn another_same_user_process_is_indistinguishable_from_the_agent_and_is_not_attributed_to_it() {
    let dir = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway().await;
    let (proxy, _audit) = start_proxy(&gateway, Some(LABEL_A), dir.path()).await;

    let from_agent = connect_status(proxy).await;
    let from_other = connect_status_from_another_process(proxy).await;
    assert!(from_agent.contains("200"), "{from_agent:?}");
    assert!(
        from_other.contains("200"),
        "measured: a second process with no secret is served by the proxy: {from_other:?}"
    );
    let claims = seen.lock().unwrap().clone();
    assert_eq!(claims.len(), 2, "{claims:?}");
    assert_eq!(
        claims[0], claims[1],
        "the gateway cannot tell the agent's connection from the other process's"
    );
    assert!(
        claims.iter().all(|(agent, token)| agent.is_empty() && token.is_empty()),
        "and neither is attributed to anyone, in particular not to {LABEL_A}: {claims:?}"
    );
}
