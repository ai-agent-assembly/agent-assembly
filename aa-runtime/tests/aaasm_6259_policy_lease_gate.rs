//! AAASM-6259 — `PolicyLeaseGate` through the real pipeline loop.
//!
//! The mock gateway counts how often it is asked, so "denied before the
//! gateway" and "permitted and forwarded" are observed, not inferred. No
//! production wiring exists yet; these drive the gate the way the later
//! wiring will, through `run_with_lease_gate`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aa_policy::resolve::classify;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    ActionContext, BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest, ToolCallContext,
};
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame, IpcResponse};
use aa_runtime::lease::decide::{GovernedIssuance, LeaseGovernance};
use aa_runtime::lease::gate::{PolicyLeaseGate, Snapshot};
use aa_runtime::op_control::OpControlStore;
use aa_runtime::pipeline::enforcement::EnforcementConfig;
use aa_runtime::pipeline::{run_with_lease_gate, LeaseGate, PipelineConfig, PipelineEvent, PipelineMetrics};
use aa_runtime::policy::PolicyRules;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const SERVER_AGENT: &str = "server-agent";

/// Mock gateway that allows everything and counts how often it was asked.
struct CountingGateway(Arc<AtomicUsize>);

#[tonic::async_trait]
impl PolicyService for CountingGateway {
    async fn check_action(&self, _r: Request<CheckActionRequest>) -> Result<Response<CheckActionResponse>, Status> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(CheckActionResponse {
            decision: Decision::Allow as i32,
            reason: "gateway-allow".to_string(),
            ..Default::default()
        }))
    }

    async fn batch_check(&self, _r: Request<BatchCheckRequest>) -> Result<Response<BatchCheckResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }

    type OpControlStreamStream = std::pin::Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send>>;

    async fn op_control_stream(
        &self,
        _r: Request<OpControlSubscribeRequest>,
    ) -> Result<Response<Self::OpControlStreamStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

async fn start_gateway(calls: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        Server::builder()
            .add_service(PolicyServiceServer::new(CountingGateway(calls)))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock gateway serve");
    });
    addr
}

async fn gateway_client(calls: Arc<AtomicUsize>) -> Arc<Mutex<GatewayClient>> {
    let addr = start_gateway(calls).await;
    Arc::new(Mutex::new(
        GatewayClient::connect(&format!("http://{addr}"))
            .await
            .expect("connect mock gateway"),
    ))
}

const POLICY: &str = "tools:
  calc: { allow: true, capabilities: [none] }
  reader: { allow: true, capabilities: [filesystem_read] }
  writer: { allow: true, capabilities: [filesystem_write] }
authority:
  leases:
    - domain: filesystem_read
      scope: whole
      reason: test
";

fn governance_issued(subject: &str, issued_at: SystemTime, ttl: u64) -> LeaseGovernance {
    let resolution = classify(Path::new("policy.yaml"), POLICY);
    LeaseGovernance::from_resolution(
        &resolution,
        subject,
        &GovernedIssuance {
            issued_at,
            default_ttl_seconds: ttl,
            default_issuer: "test".to_string(),
            id_prefix: "gov".to_string(),
        },
    )
    .expect("governance builds")
}

fn governed_gate(subject: &str) -> Arc<PolicyLeaseGate> {
    Arc::new(PolicyLeaseGate::new(Snapshot::governed(
        governance_issued(subject, SystemTime::now() - Duration::from_secs(5), 3_600),
        BTreeSet::new(),
        1,
    )))
}

fn tool_call(name: &str) -> CheckActionRequest {
    CheckActionRequest {
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: name.to_string(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    }
}

fn typed(action: ActionType) -> CheckActionRequest {
    CheckActionRequest {
        action_type: action as i32,
        ..Default::default()
    }
}

/// Send one request through the real loop under `gate`; `server_agent` is the
/// pipeline's server-side identity.
async fn ask(
    gate: &Arc<PolicyLeaseGate>,
    server_agent: &str,
    req: CheckActionRequest,
    calls: &Arc<AtomicUsize>,
) -> CheckActionResponse {
    let client = gateway_client(calls.clone()).await;
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(8);
    let (broadcast_tx, _keep) = broadcast::channel::<PipelineEvent>(8);
    let router = new_response_router();
    let (resp_tx, mut resp_rx) = mpsc::channel::<IpcResponse>(8);
    router.write().await.insert(0, resp_tx);
    let token = CancellationToken::new();
    tokio::spawn(run_with_lease_gate(
        rx,
        broadcast_tx,
        PipelineConfig {
            input_buffer: 64,
            batch_size: 100,
            flush_interval: Duration::from_millis(10_000),
            broadcast_capacity: 64,
            agent_id: server_agent.to_string(),
            enforcement: EnforcementConfig::default(),
            gateway_fail_closed: true,
            gateway_timeout: Duration::from_secs(5),
            min_sdk_version: None,
        },
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(PolicyRules::default()),
        router,
        ApprovalQueue::new(),
        Some(client),
        OpControlStore::new(),
        Arc::new(AtomicU64::new(0)),
        new_verified_identity_store(),
        Some(gate.clone() as Arc<dyn LeaseGate>),
    ));
    tx.send((0, IpcFrame::PolicyQuery(req))).await.unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), resp_rx.recv()).await;
    token.cancel();
    match resp {
        Ok(Some(IpcResponse::PolicyResponse(r))) => r,
        other => panic!("no policy response: {other:?}"),
    }
}

fn assert_denied_before_gateway(resp: &CheckActionResponse, calls: &Arc<AtomicUsize>, before: usize, why: &str) {
    assert_eq!(resp.decision, Decision::Deny as i32, "{why}: {resp:?}");
    assert!(
        resp.reason.contains("capability lease required"),
        "{why}: SDK sees only the generic message, got {:?}",
        resp.reason
    );
    assert_eq!(calls.load(Ordering::SeqCst), before, "{why}: gateway must not be asked");
}

fn assert_forwarded(resp: &CheckActionResponse, calls: &Arc<AtomicUsize>, before: usize, why: &str) {
    assert_eq!(resp.decision, Decision::Allow as i32, "{why}: {resp:?}");
    assert_eq!(resp.reason, "gateway-allow", "{why}");
    assert_eq!(calls.load(Ordering::SeqCst), before + 1, "{why}: gateway asked once");
}

#[tokio::test]
async fn permitted_requests_reach_the_gateway_and_denied_ones_never_do() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = governed_gate(SERVER_AGENT);

    // Permit: no lease needed, leased class, and the two lease-free action types.
    let mut seen = 0;
    for (label, req) in [
        ("[none] tool", tool_call("calc")),
        ("leased class", tool_call("reader")),
        ("llm call", typed(ActionType::LlmCall)),
        ("tool result", typed(ActionType::ToolResult)),
    ] {
        let resp = ask(&gate, SERVER_AGENT, req, &calls).await;
        assert_forwarded(&resp, &calls, seen, label);
        seen += 1;
    }

    // Deny: nothing may reach the gateway.
    for (label, req) in [
        ("unleased class", tool_call("writer")),
        ("undeclared tool", tool_call("ghost")),
        ("no tool name", tool_call("")),
        ("file operation", typed(ActionType::FileOperation)),
        ("network call", typed(ActionType::NetworkCall)),
        ("process exec", typed(ActionType::ProcessExec)),
        ("unspecified", typed(ActionType::ActionUnspecified)),
    ] {
        let resp = ask(&gate, SERVER_AGENT, req, &calls).await;
        assert_denied_before_gateway(&resp, &calls, seen, label);
    }
}

#[tokio::test]
async fn an_expired_lease_denies_through_the_pipeline() {
    let calls = Arc::new(AtomicUsize::new(0));
    // Issued two hours ago with a one-minute TTL: lapsed by the pipeline's own clock read.
    let lapsed = governance_issued(SERVER_AGENT, SystemTime::now() - Duration::from_secs(7_200), 60);
    let gate = Arc::new(PolicyLeaseGate::new(Snapshot::governed(lapsed, BTreeSet::new(), 1)));

    let resp = ask(&gate, SERVER_AGENT, tool_call("reader"), &calls).await;
    assert_denied_before_gateway(&resp, &calls, 0, "expired lease");
    // Control: a tool that needs no lease is unaffected by the lapse.
    let resp = ask(&gate, SERVER_AGENT, tool_call("calc"), &calls).await;
    assert_forwarded(&resp, &calls, 0, "[none] tool under a lapsed lease");
}

#[tokio::test]
async fn installing_a_new_snapshot_changes_the_next_verdict() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = governed_gate(SERVER_AGENT);

    let resp = ask(&gate, SERVER_AGENT, tool_call("reader"), &calls).await;
    assert_forwarded(&resp, &calls, 0, "before revocation");

    // Revocation: same governance, the lease id is now in the revoked set.
    let revoked: BTreeSet<String> = ["gov-0".to_string()].into();
    gate.install(Snapshot::governed(
        governance_issued(SERVER_AGENT, SystemTime::now() - Duration::from_secs(5), 3_600),
        revoked,
        2,
    ))
    .unwrap();
    let resp = ask(&gate, SERVER_AGENT, tool_call("reader"), &calls).await;
    assert_denied_before_gateway(&resp, &calls, 1, "revoked lease");

    gate.install(Snapshot::deny_all("state unreadable", 3)).unwrap();
    let resp = ask(&gate, SERVER_AGENT, tool_call("calc"), &calls).await;
    assert_denied_before_gateway(&resp, &calls, 1, "deny_all, even for a [none] tool");
}

#[tokio::test]
async fn the_subject_is_the_servers_agent_id_and_never_the_sdks_claim() {
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = governed_gate(SERVER_AGENT);

    // A request claiming to be the governed agent, on a runtime whose own id is
    // different, must not borrow the governed agent's leases.
    let mut forged = tool_call("reader");
    forged.agent_id = Some(ProtoAgentId {
        agent_id: SERVER_AGENT.to_string(),
        ..Default::default()
    });
    let resp = ask(&gate, "some-other-runtime-agent", forged, &calls).await;
    assert_denied_before_gateway(&resp, &calls, 0, "server id differs from the governed subject");

    // And claiming to be someone else does not hurt the governed agent.
    let mut other = tool_call("reader");
    other.agent_id = Some(ProtoAgentId {
        agent_id: "someone-else".to_string(),
        ..Default::default()
    });
    let resp = ask(&gate, SERVER_AGENT, other, &calls).await;
    assert_forwarded(&resp, &calls, 0, "forged agent_id has no effect");
}
