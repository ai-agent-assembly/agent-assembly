//! AAASM-6259 (J81) — the runtime capability-lease gate seam.
//!
//! Drives the public `run_with_lease_gate` loop with an in-test fake gate. The
//! real supervisor-backed gate and its lease source do not exist yet, so these
//! tests prove the seam's *placement and fail-closed semantics*, not lease
//! issuance. Every allow is paired with a deny that differs in exactly one
//! variable.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse, OpControlSignal};
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame, IpcResponse};
use aa_runtime::op_control::{agent_halt_op_id, OpControlStore};
use aa_runtime::pipeline::{
    enforcement::EnforcementConfig, run, run_with_lease_gate, LeaseDenial, LeaseGate, LeaseGateError, LeaseVerdict,
    PipelineConfig, PipelineEvent, PipelineMetrics,
};
use aa_runtime::policy::{PolicyRule, PolicyRules};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

const SERVER_AGENT: &str = "server-agent";

#[derive(Clone, Copy)]
enum LeaseState {
    Valid,
    Expired,
    Revoked,
}

/// In-memory fake. A "restart" is a fresh `FakeGate::default()`: nothing is
/// remembered, so everything is denied until leases are re-attested.
#[derive(Default)]
struct FakeGate {
    // subject -> (state, covered actions). An action absent from every entry
    // is "unmapped".
    leases: Mutex<HashMap<String, (LeaseState, Vec<ActionType>)>>,
    mapped: Vec<ActionType>,
    fail: bool,
    panic: bool,
}

impl FakeGate {
    fn with_lease(subject: &str, state: LeaseState, actions: &[ActionType]) -> Self {
        let g = FakeGate {
            mapped: vec![ActionType::ToolCall, ActionType::FileOperation],
            ..Default::default()
        };
        g.leases
            .lock()
            .unwrap()
            .insert(subject.to_string(), (state, actions.to_vec()));
        g
    }
}

impl LeaseGate for FakeGate {
    fn check(&self, subject: &str, action: ActionType) -> Result<LeaseVerdict, LeaseGateError> {
        if self.panic {
            panic!("fake gate panic");
        }
        if self.fail {
            return Err(LeaseGateError("store unavailable".into()));
        }
        if !self.mapped.contains(&action) {
            return Ok(LeaseVerdict::Deny(LeaseDenial::UnmappedAction));
        }
        let leases = self.leases.lock().unwrap();
        // Another subject holds a lease for this action but this one does not.
        let Some((state, actions)) = leases.get(subject) else {
            return Ok(LeaseVerdict::Deny(if leases.is_empty() {
                LeaseDenial::NoLease
            } else {
                LeaseDenial::WrongSubject
            }));
        };
        if !actions.contains(&action) {
            return Ok(LeaseVerdict::Deny(LeaseDenial::NoLease));
        }
        Ok(match state {
            LeaseState::Valid => LeaseVerdict::Permit,
            LeaseState::Expired => LeaseVerdict::Deny(LeaseDenial::Expired),
            LeaseState::Revoked => LeaseVerdict::Deny(LeaseDenial::Revoked),
        })
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

/// One query through the real loop. `sdk_agent` is the SDK-asserted id.
async fn ask(
    gate: Option<Arc<dyn LeaseGate>>,
    action: i32,
    sdk_agent: &str,
    policy: PolicyRules,
    op_control: OpControlStore,
    use_plain_run: bool,
) -> CheckActionResponse {
    ask_as(gate, action, sdk_agent, SERVER_AGENT, policy, op_control, use_plain_run).await
}

/// Like [`ask`] but with an explicit server-side (`PipelineConfig`) agent id.
async fn ask_as(
    gate: Option<Arc<dyn LeaseGate>>,
    action: i32,
    sdk_agent: &str,
    server_agent: &str,
    policy: PolicyRules,
    op_control: OpControlStore,
    use_plain_run: bool,
) -> CheckActionResponse {
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
            agent_id: server_agent.to_string(),
            ..config()
        },
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(policy),
        router,
        ApprovalQueue::new(),
        None,
        op_control,
        Arc::new(AtomicU64::new(0)),
        new_verified_identity_store(),
    );
    if use_plain_run {
        let (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) = args;
        tokio::spawn(run(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11));
    } else {
        let (a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) = args;
        tokio::spawn(run_with_lease_gate(
            a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, gate,
        ));
    }
    tx.send((
        0,
        IpcFrame::PolicyQuery(CheckActionRequest {
            action_type: action,
            agent_id: Some(ProtoAgentId {
                agent_id: sdk_agent.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
    ))
    .await
    .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx.recv())
        .await
        .expect("response timed out")
        .expect("channel closed");
    token.cancel();
    match resp {
        IpcResponse::PolicyResponse(r) => r,
        other => panic!("expected PolicyResponse, got {other:?}"),
    }
}

fn gate(g: FakeGate) -> Option<Arc<dyn LeaseGate>> {
    Some(Arc::new(g))
}

async fn decide(g: Option<Arc<dyn LeaseGate>>, action: ActionType, sdk_agent: &str) -> i32 {
    ask(
        g,
        action as i32,
        sdk_agent,
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await
    .decision
}

const ALLOW: i32 = Decision::Allow as i32;
const DENY: i32 = Decision::Deny as i32;

#[tokio::test]
async fn gate_absent_is_identical_to_plain_run_and_allows() {
    let via_run = ask(
        None,
        ActionType::ToolCall as i32,
        "x",
        PolicyRules::default(),
        OpControlStore::new(),
        true,
    )
    .await;
    let via_none = ask(
        None,
        ActionType::ToolCall as i32,
        "x",
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(via_run, via_none);
    assert_eq!(via_run.decision, ALLOW);
}

#[tokio::test]
async fn valid_lease_permits_and_gate_present_without_lease_denies() {
    let ok = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(ok), ActionType::ToolCall, "x").await, ALLOW);
    // One variable changed: the lease is absent.
    let none = FakeGate {
        mapped: vec![ActionType::ToolCall],
        ..Default::default()
    };
    let r = ask(
        gate(none),
        ActionType::ToolCall as i32,
        "x",
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("no_lease"), "{}", r.reason);
}

#[tokio::test]
async fn expired_and_revoked_leases_deny() {
    for (state, token) in [(LeaseState::Expired, "expired"), (LeaseState::Revoked, "revoked")] {
        let g = FakeGate::with_lease(SERVER_AGENT, state, &[ActionType::ToolCall]);
        let r = ask(
            gate(g),
            ActionType::ToolCall as i32,
            "x",
            PolicyRules::default(),
            OpControlStore::new(),
            false,
        )
        .await;
        assert_eq!(r.decision, DENY, "{token}");
        assert!(r.reason.contains(token), "{}", r.reason);
    }
}

#[tokio::test]
async fn sdk_asserted_agent_id_cannot_borrow_another_subjects_lease() {
    // The lease belongs to "victim". The server-side id is SERVER_AGENT.
    let mk = || FakeGate::with_lease("victim", LeaseState::Valid, &[ActionType::ToolCall]);
    // SDK claims to be the lease holder: still denied, the gate is keyed by the server id.
    assert_eq!(decide(gate(mk()), ActionType::ToolCall, "victim").await, DENY);
    // Control: when the lease is held by the server-side id, the SDK claim is irrelevant.
    let own = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(own), ActionType::ToolCall, "victim").await, ALLOW);
}

#[tokio::test]
async fn unmapped_and_unknown_actions_deny() {
    // Mapped action with a valid lease allows; the same lease on an unmapped
    // action (Network is not in the fake's mapped set) denies.
    let g = || {
        FakeGate::with_lease(
            SERVER_AGENT,
            LeaseState::Valid,
            &[ActionType::ToolCall, ActionType::NetworkCall],
        )
    };
    assert_eq!(decide(gate(g()), ActionType::ToolCall, "x").await, ALLOW);
    assert_eq!(decide(gate(g()), ActionType::NetworkCall, "x").await, DENY);
    // A wire code that is no ActionType at all never reaches the gate.
    let r = ask(
        gate(g()),
        9999,
        "x",
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("unmapped_action"));
}

#[tokio::test]
async fn gate_error_and_gate_panic_deny() {
    let healthy = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(healthy), ActionType::ToolCall, "x").await, ALLOW);
    for (fail, panic) in [(true, false), (false, true)] {
        let g = FakeGate {
            mapped: vec![ActionType::ToolCall],
            fail,
            panic,
            ..Default::default()
        };
        let r = ask(
            gate(g),
            ActionType::ToolCall as i32,
            "x",
            PolicyRules::default(),
            OpControlStore::new(),
            false,
        )
        .await;
        assert_eq!(r.decision, DENY);
        assert!(r.reason.contains("gate_failure"), "{}", r.reason);
    }
}

#[tokio::test]
async fn a_gate_with_no_leases_denies_what_a_leased_gate_allowed() {
    // NOT restart evidence: this is the no-lease deny under another name. A real
    // restart test needs a real store and a re-attestation step (open decision).
    let before = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(before), ActionType::ToolCall, "x").await, ALLOW);
    // The production store design is an open decision; an in-memory store
    // simply forgets, which fails closed.
    let after = FakeGate {
        mapped: vec![ActionType::ToolCall],
        ..Default::default()
    };
    assert_eq!(decide(gate(after), ActionType::ToolCall, "x").await, DENY);
}

#[tokio::test]
async fn an_empty_server_subject_is_denied_even_if_the_gate_would_permit_it() {
    // Control: same gate shape, non-empty holder == server subject -> allowed.
    let ok = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(ok), ActionType::ToolCall, "x").await, ALLOW);
    // The gate holds a valid lease for subject "" and would Permit it; only the
    // caller's own empty-subject guard stands between that and an allow.
    let empty_holder = FakeGate::with_lease("", LeaseState::Valid, &[ActionType::ToolCall]);
    let r = ask_as(
        gate(empty_holder),
        ActionType::ToolCall as i32,
        "x",
        "",
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("no_subject"), "{}", r.reason);
}

#[tokio::test]
async fn an_unspecified_action_is_denied_even_if_the_gate_would_permit_it() {
    // Control: a leased, mapped ToolCall is allowed.
    let ok = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    assert_eq!(decide(gate(ok), ActionType::ToolCall, "x").await, ALLOW);
    // A gate that maps and permits Unspecified must still be overruled.
    let mut permissive = FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ActionUnspecified]);
    // `with_lease` maps only ToolCall/FileOperation, so without this the FAKE
    // would deny Unspecified itself and the caller's guard would go untested.
    permissive.mapped.push(ActionType::ActionUnspecified);
    let r = ask(
        gate(permissive),
        ActionType::ActionUnspecified as i32,
        "x",
        PolicyRules::default(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("unmapped_action"), "{}", r.reason);
}

#[tokio::test]
async fn permit_cannot_override_local_policy_deny() {
    let policy = || PolicyRules {
        rules: vec![PolicyRule {
            name: "block-tool".into(),
            blocked_actions: vec![ActionType::ToolCall.as_str_name().to_string()],
            ..Default::default()
        }],
    };
    let g = || FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    let r = ask(
        gate(g()),
        ActionType::ToolCall as i32,
        "x",
        policy(),
        OpControlStore::new(),
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("block-tool"), "{}", r.reason);
}

#[tokio::test]
async fn permit_cannot_override_op_control_terminate() {
    let g = || FakeGate::with_lease(SERVER_AGENT, LeaseState::Valid, &[ActionType::ToolCall]);
    let halted = OpControlStore::new();
    halted.apply(&agent_halt_op_id(SERVER_AGENT), OpControlSignal::Terminate);
    let r = ask(
        gate(g()),
        ActionType::ToolCall as i32,
        "x",
        PolicyRules::default(),
        halted,
        false,
    )
    .await;
    assert_eq!(r.decision, DENY);
    assert!(r.reason.contains("OpTerminatedError"), "{}", r.reason);
}
