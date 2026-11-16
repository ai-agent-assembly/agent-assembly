//! AAASM-6261 (J83) AC2: the gateway's network decision is attributed to the
//! launch that opened the connection.
//!
//! `aasm run` starts one proxy per launch and hands it that launch's label in
//! `AA_AGENT_ID`. Before this change the proxy's own audit record carried the
//! label but the `CheckAction` it sent to the gateway always said `aa-proxy`, so
//! the gateway's decision and its audit entry could not tell two launches apart.
//!
//! The label is *asserted*, not verified: the request carries no
//! `credential_token`. These tests pin the attribution by value; they do not
//! claim authentication.
//!
//! Two proxies share one gateway on purpose. A single shared proxy attributing
//! each request to a different agent is rejected by ADR 0033 §6, so the unit of
//! identity under test is the proxy a launch owns, not the connection.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_proxy::audit_jsonl::{ProxyAuditDecision, ProxyAuditEntry, RefusalRule};
use aa_proxy::config::{CredentialAction, ProxyConfig};
use aa_proxy::tls::CaStore;
use aa_runtime::pipeline::PipelineEvent;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

const HOST: &str = "hooks.example.com";
const LAUNCH_A: &str = "launch-a-agent";
const LAUNCH_B: &str = "launch-b-agent";
/// What a proxy without a launch label sends, and so what "unattributed" means
/// to the gateway. Duplicated from `aa_proxy::mcp_enforce::PROXY_AGENT_ID` on
/// purpose: a test that imported the constant would pass if the constant were
/// changed to equal a launch label.
const UNATTRIBUTED: &str = "aa-proxy";

/// Allows every `NetworkCall` except one claimed by `denied_agent`, and records
/// the agent id each request claimed. Decides by the claimed id and nothing
/// else, so a verdict can only differ between two proxies if the id did.
struct DenyByClaimedAgent {
    denied_agent: String,
    seen: Arc<Mutex<Vec<String>>>,
}

#[tonic::async_trait]
impl PolicyService for DenyByClaimedAgent {
    async fn check_action(&self, req: Request<CheckActionRequest>) -> Result<Response<CheckActionResponse>, Status> {
        let request = req.get_ref();
        let is_network = matches!(
            request.context.as_ref().and_then(|c| c.action.as_ref()),
            Some(Action::NetworkCall(_))
        );
        let claimed = request
            .agent_id
            .as_ref()
            .map(|a| a.agent_id.clone())
            .unwrap_or_default();
        if is_network {
            self.seen.lock().unwrap().push(claimed.clone());
        }
        let deny = is_network && claimed == self.denied_agent;
        Ok(Response::new(CheckActionResponse {
            decision: if deny {
                aa_proto::assembly::common::v1::Decision::Deny as i32
            } else {
                aa_proto::assembly::common::v1::Decision::Allow as i32
            },
            reason: if deny {
                format!("network egress denied for {claimed}")
            } else {
                String::new()
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

async fn spawn_gateway(denied_agent: &str) -> (String, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let service = DenyByClaimedAgent {
        denied_agent: denied_agent.to_string(),
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
    agent_id: Option<&str>,
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
        agent_id: agent_id.map(str::to_string),
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

async fn next_record(rx: &mut mpsc::Receiver<ProxyAuditEntry>) -> ProxyAuditEntry {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("the proxy persisted no audit record within 5 s")
        .expect("audit channel closed")
}

/// The gateway sees each launch's own label: a gateway that decides by the
/// claimed id (a stand-in for any consumer of it) gets a different answer for
/// each launch's connection.
#[tokio::test]
async fn each_launch_reaches_the_gateway_under_its_own_label() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway(LAUNCH_B).await;
    let (proxy_a, _audit_a) = start_proxy(&gateway, Some(LAUNCH_A), dir_a.path()).await;
    let (proxy_b, mut audit_b) = start_proxy(&gateway, Some(LAUNCH_B), dir_b.path()).await;

    let status_a = connect_status(proxy_a).await;
    assert!(
        status_a.contains("200"),
        "launch A is not the denied agent and must be allowed, got: {status_a:?}"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![LAUNCH_A.to_string()],
        "the gateway must have been asked about launch A under its own label"
    );

    let status_b = connect_status(proxy_b).await;
    assert!(
        !status_b.contains("200"),
        "launch B is the agent the gateway denies and must be refused, got: {status_b:?}"
    );
    assert_eq!(
        *seen.lock().unwrap(),
        vec![LAUNCH_A.to_string(), LAUNCH_B.to_string()],
        "each connection must reach the gateway under the label of the proxy that carried it"
    );

    // The proxy's own record already named the launch; the point is that the
    // gateway's view and the proxy's view now agree on who it was.
    let refusal = next_record(&mut audit_b).await;
    assert_eq!(refusal.decision, ProxyAuditDecision::Blocked);
    assert_eq!(refusal.refusal_rule, Some(RefusalRule::GatewayEgressPolicy));
    assert_eq!(refusal.agent_id.as_deref(), Some(LAUNCH_B));
}

/// A proxy started without a label stays explicitly unattributed to the
/// gateway. This is the negative control for the label tests above: if the
/// proxy invented a label, or if the stub keyed on anything but the claimed id,
/// the unlabelled proxy would not be distinguishable from a launch.
#[tokio::test]
async fn a_proxy_without_a_label_stays_unattributed() {
    let dir = tempfile::tempdir().unwrap();
    let (gateway, seen) = spawn_gateway(LAUNCH_B).await;
    let (unlabelled, _audit) = start_proxy(&gateway, None, dir.path()).await;

    let status = connect_status(unlabelled).await;
    assert!(status.contains("200"), "got: {status:?}");
    assert_eq!(*seen.lock().unwrap(), vec![UNATTRIBUTED.to_string()]);

    let dir_empty = tempfile::tempdir().unwrap();
    let (empty_label, _audit_empty) = start_proxy(&gateway, Some(""), dir_empty.path()).await;
    let status = connect_status(empty_label).await;
    assert!(status.contains("200"), "got: {status:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![UNATTRIBUTED.to_string(), UNATTRIBUTED.to_string()],
        "an empty label is no label"
    );
}
