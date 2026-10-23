//! AAASM-6259 — the runtime capability-lease gate seam.
//!
//! Drives the public pipeline loop with a test-double gate. No production gate
//! exists yet, so these prove the seam's placement and fail-closed semantics,
//! not lease issuance.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use aa_proto::assembly::common::v1::{ActionType, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
use aa_proto::assembly::policy::v1::{
    BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
    OpControlSubscribeRequest,
};
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::gateway_client::GatewayClient;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame, IpcResponse};
use aa_runtime::op_control::OpControlStore;
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

/// Send one policy query through the real loop; `None` if no response arrives
/// (the pipeline task died).
async fn try_ask(
    entry: Entry,
    action: i32,
    policy: PolicyRules,
    gateway: Option<Arc<Mutex<GatewayClient>>>,
) -> Option<CheckActionResponse> {
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(8);
    let (broadcast_tx, _keep) = broadcast::channel::<PipelineEvent>(8);
    let router = new_response_router();
    let (resp_tx, mut resp_rx) = mpsc::channel::<IpcResponse>(8);
    router.write().await.insert(0, resp_tx);
    let token = CancellationToken::new();
    let args = (
        rx,
        broadcast_tx,
        config(),
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(policy),
        router,
        ApprovalQueue::new(),
        gateway,
        OpControlStore::new(),
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
            action_type: action,
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx.recv()).await;
    token.cancel();
    match resp {
        Ok(Some(IpcResponse::PolicyResponse(r))) => Some(r),
        _ => None,
    }
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

#[tokio::test]
async fn gate_absent_unchanged() {
    let actions = [
        ActionType::LlmCall,
        ActionType::ToolCall,
        ActionType::FileOperation,
        ActionType::ToolResult,
    ];
    for action in actions {
        let plain = ask(Entry::PlainRun, action, blocking_policy("TOOL_CALL"), None).await;
        let no_gate = ask(Entry::WithGate(None), action, blocking_policy("TOOL_CALL"), None).await;
        assert_eq!(
            plain, no_gate,
            "{action:?}: absent gate must equal the pre-seam entry point"
        );
    }
    // Control: the comparison is not vacuous; the policy really denies TOOL_CALL.
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

#[tokio::test]
async fn passthrough_classes_not_gated() {
    for action in [ActionType::LlmCall, ActionType::ToolResult] {
        let gate = RecordingGate::new(deny);
        let resp = ask(gate_entry(&gate), action, PolicyRules::default(), None).await;
        assert_eq!(
            resp.decision,
            Decision::Allow as i32,
            "{action:?} must not be denied by the gate"
        );
        assert!(gate.calls().is_empty(), "{action:?} must not consult the gate");
    }

    // Controls: a capability action and unclassifiable codes ARE consulted.
    for code in [ActionType::ToolCall as i32, ActionType::ActionUnspecified as i32, 99] {
        let gate = RecordingGate::new(deny);
        let resp = try_ask(gate_entry(&gate), code, PolicyRules::default(), None)
            .await
            .expect("response");
        assert_eq!(resp.decision, Decision::Deny as i32, "code {code} must reach the gate");
        assert_eq!(gate.calls().len(), 1, "code {code}");
    }
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
