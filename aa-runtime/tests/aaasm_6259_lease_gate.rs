//! AAASM-6259 — the runtime capability-lease gate seam.
//!
//! Drives the public pipeline loop with a test-double gate. No production gate
//! exists yet, so these prove the seam's placement and fail-closed semantics,
//! not lease issuance.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage, OpControlSignal,
    OpControlSubscribeRequest,
};
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame, IpcResponse};
use aa_runtime::op_control::{agent_halt_op_id, OpControlStore};
use aa_runtime::pipeline::enforcement::EnforcementConfig;
use aa_runtime::pipeline::{
    run, run_with_lease_gate, LeaseGate, LeaseVerdict, PipelineConfig, PipelineEvent, PipelineMetrics,
};
use aa_runtime::policy::{PolicyRule, PolicyRules};
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

/// Test-double gate. Records every call; verdict comes from `verdict`.
struct RecordingGate {
    calls: StdMutex<Vec<(String, SystemTime)>>,
    verdict: Box<dyn Fn() -> LeaseVerdict + Send + Sync>,
}

impl RecordingGate {
    fn new(verdict: impl Fn() -> LeaseVerdict + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            calls: StdMutex::new(Vec::new()),
            verdict: Box::new(verdict),
        })
    }
    fn calls(&self) -> Vec<(String, SystemTime)> {
        self.calls.lock().unwrap().clone()
    }
}

impl LeaseGate for RecordingGate {
    fn check(&self, subject: &str, _req: &CheckActionRequest, now: SystemTime) -> LeaseVerdict {
        self.calls.lock().unwrap().push((subject.to_string(), now));
        (self.verdict)()
    }
}

fn deny() -> LeaseVerdict {
    LeaseVerdict::Deny {
        reason: "no lease".to_string(),
    }
}

fn blocking_policy(action: &str) -> PolicyRules {
    PolicyRules {
        rules: vec![PolicyRule {
            name: "block-rule".to_string(),
            blocked_actions: vec![action.to_string()],
            ..Default::default()
        }],
    }
}

fn config() -> PipelineConfig {
    PipelineConfig {
        input_buffer: 64,
        batch_size: 100,
        flush_interval: Duration::from_millis(10_000),
        broadcast_capacity: 64,
        agent_id: SERVER_AGENT.to_string(),
        enforcement: EnforcementConfig::default(),
        gateway_fail_closed: true,
        gateway_timeout: Duration::from_secs(5),
        min_sdk_version: None,
    }
}

/// How the query reaches the pipeline.
enum Entry {
    /// The pre-existing `run` entry point, which has no gate parameter.
    PlainRun,
    /// `run_with_lease_gate`, with or without a gate.
    WithGate(Option<Arc<dyn LeaseGate>>),
}

/// Knobs for one query. Defaults: the standard server agent, no SDK-asserted
/// agent, a fresh op-control store.
struct Query {
    action: i32,
    policy: PolicyRules,
    gateway: Option<Arc<Mutex<GatewayClient>>>,
    server_agent: String,
    sdk_agent: Option<String>,
    op_control: OpControlStore,
    wait: Duration,
}

impl Query {
    fn new(action: i32) -> Self {
        Self {
            action,
            policy: PolicyRules::default(),
            gateway: None,
            server_agent: SERVER_AGENT.to_string(),
            sdk_agent: None,
            op_control: OpControlStore::new(),
            wait: Duration::from_secs(2),
        }
    }
}

/// Send one policy query through the real loop; `None` if no response arrives
/// (the pipeline task died, or the query is blocked).
async fn try_ask_with(entry: Entry, q: Query) -> Option<CheckActionResponse> {
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(8);
    let (broadcast_tx, _keep) = broadcast::channel::<PipelineEvent>(8);
    let router = new_response_router();
    let (resp_tx, mut resp_rx) = mpsc::channel::<IpcResponse>(8);
    router.write().await.insert(0, resp_tx);
    let token = CancellationToken::new();
    let args = (
        rx,
        broadcast_tx,
        PipelineConfig {
            agent_id: q.server_agent.clone(),
            ..config()
        },
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(q.policy),
        router,
        ApprovalQueue::new(),
        q.gateway,
        q.op_control,
        Arc::new(AtomicU64::new(0)),
        new_verified_identity_store(),
    );
    let (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) = args;
    match entry {
        Entry::PlainRun => {
            tokio::spawn(run(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11));
        }
        Entry::WithGate(gate) => {
            tokio::spawn(run_with_lease_gate(
                a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, gate,
            ));
        }
    }
    tx.send((
        0,
        IpcFrame::PolicyQuery(CheckActionRequest {
            action_type: q.action,
            agent_id: q.sdk_agent.map(|agent_id| ProtoAgentId {
                agent_id,
                ..Default::default()
            }),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    let resp = tokio::time::timeout(q.wait, resp_rx.recv()).await;
    token.cancel();
    match resp {
        Ok(Some(IpcResponse::PolicyResponse(r))) => Some(r),
        _ => None,
    }
}

async fn try_ask(
    entry: Entry,
    action: i32,
    policy: PolicyRules,
    gateway: Option<Arc<Mutex<GatewayClient>>>,
) -> Option<CheckActionResponse> {
    try_ask_with(
        entry,
        Query {
            policy,
            gateway,
            ..Query::new(action)
        },
    )
    .await
}

async fn ask(
    entry: Entry,
    action: ActionType,
    policy: PolicyRules,
    gateway: Option<Arc<Mutex<GatewayClient>>>,
) -> CheckActionResponse {
    try_ask(entry, action as i32, policy, gateway)
        .await
        .expect("pipeline produced no response")
}

fn gate_entry(gate: &Arc<RecordingGate>) -> Entry {
    Entry::WithGate(Some(gate.clone() as Arc<dyn LeaseGate>))
}

/// `run` and `run_with_lease_gate(None)` share one code path, so equality here
/// is a smoke check, not the guarantee. The real guarantee that an absent gate
/// changes nothing is that every pre-existing pipeline test passes unchanged
/// and that `handle_policy_query` reads the clock and calls the gate only
/// inside `if let Some(gate)`.
#[tokio::test]
async fn absent_gate_matches_pre_seam_entry_point() {
    let actions = [
        ActionType::LlmCall,
        ActionType::ToolCall,
        ActionType::FileOperation,
        ActionType::ToolResult,
    ];
    for action in actions {
        let plain = ask(Entry::PlainRun, action, blocking_policy("TOOL_CALL"), None).await;
        let no_gate = ask(Entry::WithGate(None), action, blocking_policy("TOOL_CALL"), None).await;
        assert_eq!(plain, no_gate, "{action:?}");
    }
    // Control: the policy really denies TOOL_CALL and allows the rest.
    let blocked = ask(
        Entry::PlainRun,
        ActionType::ToolCall,
        blocking_policy("TOOL_CALL"),
        None,
    )
    .await;
    assert_eq!(blocked.decision, Decision::Deny as i32);
    let allowed = ask(
        Entry::PlainRun,
        ActionType::FileOperation,
        blocking_policy("TOOL_CALL"),
        None,
    )
    .await;
    assert_eq!(allowed.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn deny_before_gateway() {
    let gateway_calls = Arc::new(AtomicUsize::new(0));
    let client = gateway_client(gateway_calls.clone()).await;
    let gate = RecordingGate::new(deny);

    let resp = ask(
        gate_entry(&gate),
        ActionType::ToolCall,
        PolicyRules::default(),
        Some(client),
    )
    .await;

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(
        resp.reason.contains("capability lease required"),
        "reason: {}",
        resp.reason
    );
    assert_eq!(
        gateway_calls.load(Ordering::SeqCst),
        0,
        "gateway must not be consulted on a lease deny"
    );
    assert_eq!(gate.calls().len(), 1);
}

#[tokio::test]
async fn permit_falls_through_to_normal_evaluation() {
    // Permit then local policy blocks: the permit must not override the deny.
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let blocked = ask(
        gate_entry(&gate),
        ActionType::ToolCall,
        blocking_policy("TOOL_CALL"),
        None,
    )
    .await;
    assert_eq!(blocked.decision, Decision::Deny as i32);
    assert!(blocked.reason.contains("blocked by rule"), "reason: {}", blocked.reason);

    // Permit then the gateway answers: the gateway is consulted and its answer relayed.
    let gateway_calls = Arc::new(AtomicUsize::new(0));
    let client = gateway_client(gateway_calls.clone()).await;
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let via_gateway = ask(
        gate_entry(&gate),
        ActionType::ToolCall,
        PolicyRules::default(),
        Some(client),
    )
    .await;
    assert_eq!(via_gateway.reason, "gateway-allow");
    assert_eq!(gateway_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gate_panic_denies() {
    let gateway_calls = Arc::new(AtomicUsize::new(0));
    let client = gateway_client(gateway_calls.clone()).await;
    let gate = RecordingGate::new(|| panic!("test gate panic"));

    let resp = ask(
        gate_entry(&gate),
        ActionType::ToolCall,
        PolicyRules::default(),
        Some(client),
    )
    .await;

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(
        gateway_calls.load(Ordering::SeqCst),
        0,
        "a panicking gate must not fall through to the gateway"
    );
}

/// `action_type` is SDK-asserted, so no class may skip the gate: a
/// non-cooperative SDK could otherwise label a shell exec as `LLM_CALL`.
#[tokio::test]
async fn gate_consulted_for_every_action_type() {
    let codes = [
        ActionType::LlmCall as i32,
        ActionType::ToolResult as i32,
        ActionType::ToolCall as i32,
        ActionType::NetworkCall as i32,
        ActionType::ProcessExec as i32,
        ActionType::ActionUnspecified as i32,
        99,
    ];
    for code in codes {
        let denying = RecordingGate::new(deny);
        let resp = try_ask(gate_entry(&denying), code, PolicyRules::default(), None)
            .await
            .expect("response");
        assert_eq!(
            resp.decision,
            Decision::Deny as i32,
            "code {code} must reach a denying gate"
        );
        assert_eq!(denying.calls().len(), 1, "code {code}");

        let permitting = RecordingGate::new(|| LeaseVerdict::Permit);
        let resp = try_ask(gate_entry(&permitting), code, PolicyRules::default(), None)
            .await
            .expect("response");
        assert_eq!(
            resp.decision,
            Decision::Allow as i32,
            "code {code} must fall through on permit"
        );
        assert_eq!(permitting.calls().len(), 1, "code {code}");
    }
}

#[tokio::test]
async fn empty_subject_denies_without_consulting_gate() {
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let resp = try_ask_with(
        gate_entry(&gate),
        Query {
            server_agent: String::new(),
            ..Query::new(ActionType::ToolCall as i32)
        },
    )
    .await
    .expect("response");
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(gate.calls().is_empty(), "a gate must not be asked about no subject");
}

#[tokio::test]
async fn sdk_asserted_agent_id_never_becomes_the_subject() {
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    try_ask_with(
        gate_entry(&gate),
        Query {
            sdk_agent: Some("attacker-chosen".to_string()),
            ..Query::new(ActionType::ToolCall as i32)
        },
    )
    .await
    .expect("response");
    let calls = gate.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, SERVER_AGENT);
}

/// The gate sits after the op-control halt: a terminated agent is denied by the
/// kill switch and the gate is never asked; a paused one blocks before it.
#[tokio::test]
async fn op_control_halt_precedes_gate() {
    let store = OpControlStore::new();
    store.apply(&agent_halt_op_id(SERVER_AGENT), OpControlSignal::Terminate);
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let resp = try_ask_with(
        gate_entry(&gate),
        Query {
            op_control: store,
            ..Query::new(ActionType::ToolCall as i32)
        },
    )
    .await
    .expect("response");
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(resp.reason.contains("OpTerminatedError"), "reason: {}", resp.reason);
    assert!(gate.calls().is_empty(), "terminated op must not reach the gate");

    let store = OpControlStore::new();
    store.apply(&agent_halt_op_id(SERVER_AGENT), OpControlSignal::Pause);
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let resp = try_ask_with(
        gate_entry(&gate),
        Query {
            op_control: store,
            wait: Duration::from_millis(300),
            ..Query::new(ActionType::ToolCall as i32)
        },
    )
    .await;
    assert!(resp.is_none(), "a paused op blocks");
    assert!(gate.calls().is_empty(), "paused op must not reach the gate");
}

/// The SDK gets a generic message; the gate's detail stays in the runtime log.
#[tokio::test]
async fn deny_reason_is_not_relayed_to_sdk() {
    const MARKER: &str = "SECRET-LEASE-DETAIL-9f3a";
    let gate = RecordingGate::new(|| LeaseVerdict::Deny {
        reason: MARKER.to_string(),
    });
    let resp = ask(gate_entry(&gate), ActionType::ToolCall, PolicyRules::default(), None).await;
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "capability lease required");
    assert!(!resp.reason.contains(MARKER));
}

fn denial_count(snapshotter: &metrics_util::debugging::Snapshotter) -> u64 {
    use metrics_util::debugging::DebugValue;
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter(|(key, _, _, _)| key.key().name() == "aa_lease_gate_denials_total")
        .map(|(_, _, _, value)| match value {
            DebugValue::Counter(n) => n,
            _ => 0,
        })
        .sum()
}

#[tokio::test]
async fn denial_increments_counter() {
    // The recorder is process-global and other tests in this binary may deny
    // concurrently under plain `cargo test`, so assert an increase, not an
    // exact delta.
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    // Only this test installs a recorder.
    let installed = recorder.install().is_ok();
    assert!(installed, "metrics recorder already installed in this test binary");

    let before = denial_count(&snapshotter);
    let deny_gate = RecordingGate::new(deny);
    ask(
        gate_entry(&deny_gate),
        ActionType::ToolCall,
        PolicyRules::default(),
        None,
    )
    .await;
    let after = denial_count(&snapshotter);
    assert!(
        after > before,
        "deny must increment aa_lease_gate_denials_total ({before} -> {after})"
    );
}

#[tokio::test]
async fn clock_passed_once() {
    let gate = RecordingGate::new(|| LeaseVerdict::Permit);
    let before = SystemTime::now();
    ask(gate_entry(&gate), ActionType::ToolCall, PolicyRules::default(), None).await;
    let after = SystemTime::now();

    let calls = gate.calls();
    assert_eq!(calls.len(), 1, "one query consults the gate once");
    let (subject, now) = &calls[0];
    assert_eq!(subject, SERVER_AGENT, "subject is the server-side identity");
    assert!(*now >= before && *now <= after, "now must be read during the query");
}
