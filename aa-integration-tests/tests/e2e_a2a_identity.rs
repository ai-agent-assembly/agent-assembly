//! AAASM-1944 / F116 ST-X — Agent Identity & Zero-trust A2A E2E.
//!
//! Acceptance attestation for spec highlight ⑥ ("Agent Identity & Zero-trust
//! A2A", spec line 7287): when agent A initiates a call to agent B, the
//! gateway records both identities and an impersonator (agent C presenting
//! A's claimed agent_id with C's own credential_token) is rejected before
//! the policy engine sees the request.
//!
//! ## Test cases
//!
//! * **ST-X-1** — Legitimate A → B call: `caller_agent_id = A`, `agent_id = B`,
//!   token matches B's registered token. Assert Allow, audit event is
//!   `A2ACallIntercepted`, payload carries both ids.
//! * **ST-X-2** — Impersonation: `agent_id = A` (claimed) sent with C's
//!   token. Assert Deny with reason "credential token mismatch", audit
//!   event is `A2AImpersonationAttempted`.
//! * **ST-X-3** — Missing token: registered agent D with empty
//!   `credential_token`. Assert Deny with reason "missing credential token",
//!   audit event is `A2AImpersonationAttempted`.
//!
//! ## Why this lives here, not in aa-gateway
//!
//! The gateway crate has unit-level coverage of `validate_credential_token`
//! and the audit event shape. This file is the F116 acceptance lens that
//! pins the contract from the operator's seat: real tonic server, real
//! `AgentRegistry`, real `record_audit` channel.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, AuditEventType, GovernanceLevel};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

async fn start_gateway(policy_fixture: &str) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let path = fixture_path(policy_fixture);
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(&path, alert_tx).expect("policy fixture loads"));
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("tonic Server::serve_with_incoming");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry, audit_rx)
}

fn register_agent(registry: &AgentRegistry, proto_id: &ProtoAgentId, credential_token: &str) {
    let key = proto_agent_id_to_key(proto_id);
    let record = AgentRecord {
        agent_id: key,
        name: proto_id.agent_id.clone(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: credential_token.into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
    };
    registry.register(record).expect("register agent");
}

fn tool_call_request(
    callee: &ProtoAgentId,
    credential_token: &str,
    caller: Option<&ProtoAgentId>,
    tool_name: &str,
    trace_id: &str,
) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(callee.clone()),
        credential_token: credential_token.into(),
        trace_id: trace_id.into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool_name.into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: caller.cloned(),
    }
}

async fn drain_audit_entries(audit_rx: &mut mpsc::Receiver<AuditEntry>) -> Vec<AuditEntry> {
    let mut out = vec![];
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_millis(50), audit_rx.recv()).await {
            Ok(Some(entry)) => out.push(entry),
            Ok(None) | Err(_) => break,
        }
    }
    out
}

fn make_id(agent_id: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: agent_id.into(),
    }
}

// ── ST-X-1 ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_x_1_legitimate_a2a_call_emits_a2a_call_intercepted_with_caller_and_callee() {
    let (addr, registry, mut audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    let agent_a = make_id("agent-a");
    let agent_b = make_id("agent-b");
    register_agent(&registry, &agent_a, "token-a");
    register_agent(&registry, &agent_b, "token-b");

    // Agent A invokes a tool exposed by agent B: token belongs to B,
    // caller_agent_id is A.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let req = tool_call_request(&agent_b, "token-b", Some(&agent_a), "read_file", "trace-a2a-1");
    let resp = client.check_action(req).await.expect("Allow path").into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "registered A → B call must be allowed by allow_deny_mixed.yaml read_file rule"
    );

    let audit_entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(audit_entries.len(), 1, "exactly one audit entry expected");
    let entry = &audit_entries[0];
    assert_eq!(
        entry.event_type(),
        AuditEventType::A2ACallIntercepted,
        "A2A allow path must emit A2ACallIntercepted (not generic ToolCallIntercepted)"
    );
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("audit payload is JSON");
    assert_eq!(payload["caller_agent_id"], "agent-a");
    assert_eq!(payload["callee_agent_id"], "agent-b");
}

// ── ST-X-2 ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_x_2_impersonation_with_wrong_token_is_rejected_and_audited() {
    let (addr, registry, mut audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    let agent_a = make_id("agent-a");
    let agent_c = make_id("agent-c");
    register_agent(&registry, &agent_a, "token-a");
    register_agent(&registry, &agent_c, "token-c");

    // Agent C tries to impersonate A: claims agent_id = A but presents
    // C's own credential_token.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let req = tool_call_request(&agent_a, "token-c", None, "read_file", "trace-impersonate");
    let resp = client.check_action(req).await.expect("Deny path").into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "impersonation (token mismatch) must be rejected before policy evaluation"
    );
    assert_eq!(resp.reason, "credential token mismatch");
    assert_eq!(resp.policy_rule, "a2a_identity_verification");

    let audit_entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(audit_entries.len(), 1, "exactly one impersonation audit entry expected");
    let entry = &audit_entries[0];
    assert_eq!(entry.event_type(), AuditEventType::A2AImpersonationAttempted);
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("audit payload is JSON");
    assert_eq!(payload["claimed_agent_id"], "agent-a");
    assert_eq!(payload["credential_token_present"], true);
    assert_eq!(payload["reason"], "credential token mismatch");
}

// ── ST-X-3 ──────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_x_3_missing_credential_token_is_rejected_pre_evaluation() {
    let (addr, registry, mut audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    let agent_d = make_id("agent-d");
    register_agent(&registry, &agent_d, "token-d");

    // Empty credential_token — must be rejected before policy evaluation.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let req = tool_call_request(&agent_d, "", None, "read_file", "trace-empty-token");
    let resp = client.check_action(req).await.expect("Deny path").into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "empty credential_token must be rejected for a registered agent"
    );
    assert_eq!(resp.reason, "missing credential token");
    assert_eq!(resp.policy_rule, "a2a_identity_verification");

    let audit_entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(audit_entries.len(), 1);
    let entry = &audit_entries[0];
    assert_eq!(entry.event_type(), AuditEventType::A2AImpersonationAttempted);
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("audit payload is JSON");
    assert_eq!(payload["claimed_agent_id"], "agent-d");
    assert_eq!(payload["credential_token_present"], false);
}
