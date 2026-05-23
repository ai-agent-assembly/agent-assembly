//! AAASM-1564 — end-to-end verification of observe-mode enforcement.
//!
//! Validates the contract laid out across AAASM-1554..AAASM-1557 actually fires
//! on the gRPC request path:
//!
//! * ST-SANDBOX-1 — Observe + deny rule → response is Allow, audit log carries
//!   a `dry_run: true` shadow event.
//! * ST-SANDBOX-2 — Observe + allow → response is Allow, no shadow metadata.
//! * ST-SANDBOX-3 — Enforce + deny → response is Deny (regression guard).
//! * ST-SANDBOX-4 — Per-agent override wins; two agents under the same deny
//!   policy resolve to different decisions based on their record's mode.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::{AuditEntry, GovernanceLevel};
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
use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

/// Start a PolicyService gRPC server with an attached AgentRegistry and a
/// caller-owned audit receiver. The receiver is the contract surface the
/// observe-mode tests inspect — every `record_audit` call lands here.
async fn start_server_with_audit_rx(policy_yaml: &str) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry, audit_rx)
}

/// Construct an `AgentRecord` carrying `enforcement_mode` and register it.
fn register_agent_with_mode(
    registry: &AgentRegistry,
    agent_name: &str,
    proto_id: &ProtoAgentId,
    mode: Option<aa_core::EnforcementMode>,
) {
    let key = proto_agent_id_to_key(proto_id);
    let record = AgentRecord {
        agent_id: key,
        name: agent_name.into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: "tok".into(),
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
        enforcement_mode: mode,
    };
    registry.register(record).unwrap();
}

fn tool_call_request_for(proto_id: &ProtoAgentId, tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_id.clone()),
        credential_token: "tok".into(),
        trace_id: format!("trace-{tool_name}"),
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
    }
}

/// Drain audit entries with a short bounded wait — `record_audit` is
/// fire-and-forget so the entry may not arrive synchronously with the
/// CheckAction response.
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

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

#[tokio::test]
async fn st_sandbox_1_observe_mode_with_deny_rule_returns_allow_and_dry_run_audit() {
    // The core ST contract: an agent registered with enforcement_mode = OBSERVE
    // hits a deny rule, the gateway returns Allow (agent NOT blocked), and the
    // audit log records exactly one entry tagged dry_run = true with
    // shadow_decision = "deny".
    let (addr, registry, mut audit_rx) = start_server_with_audit_rx(DENY_BASH_POLICY).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "observe-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "observe-agent",
        &proto_id,
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "bash"))
        .await
        .unwrap()
        .into_inner();

    // ⚠️ Agent is NOT blocked even though the policy says deny.
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "observe mode must rewrite Deny → Allow on the response"
    );

    // Shadow audit event was emitted.
    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(
        entries.len(),
        1,
        "exactly one audit entry expected, got {}",
        entries.len()
    );
    let payload: serde_json::Value = serde_json::from_str(entries[0].payload()).expect("payload is valid JSON");
    assert_eq!(payload["dry_run"], serde_json::Value::Bool(true));
    assert_eq!(payload["shadow_decision"], "deny");
}

#[tokio::test]
async fn st_sandbox_2_observe_mode_with_allow_decision_emits_no_shadow_metadata() {
    // Observe mode must NOT fabricate shadow events for already-Allow
    // decisions — otherwise audit-log shadow volume would mirror all traffic
    // instead of just would-be violations. The response is Allow either way;
    // the discriminator is whether `dry_run` appears in the audit payload.
    let allow_policy = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;
    let (addr, registry, mut audit_rx) = start_server_with_audit_rx(allow_policy).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "observe-clean-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "observe-clean-agent",
        &proto_id,
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "web_search"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32);

    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(entries.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(entries[0].payload()).expect("payload is valid JSON");
    assert!(
        payload.get("dry_run").is_none(),
        "Allow decisions in observe mode must NOT include dry_run in the audit payload, got: {payload}"
    );
    assert!(payload.get("shadow_decision").is_none());
}

#[tokio::test]
async fn st_sandbox_3_enforce_mode_with_deny_rule_still_blocks_agent() {
    // Regression guard: an agent without any per-agent override (or registered
    // with Enforce) hitting a deny policy must still be blocked. If anyone
    // ever flips the default in resolve_enforcement_mode this test catches it.
    let (addr, registry, mut audit_rx) = start_server_with_audit_rx(DENY_BASH_POLICY).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "enforce-agent".into(),
    };
    register_agent_with_mode(&registry, "enforce-agent", &proto_id, None);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request_for(&proto_id, "bash"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "enforce mode must still block deny rules — regression in {:?}",
        resp.reason
    );

    // Audit entry must be a normal Deny record, NOT a shadow event.
    let entries = drain_audit_entries(&mut audit_rx).await;
    assert_eq!(entries.len(), 1);
    let payload: serde_json::Value = serde_json::from_str(entries[0].payload()).expect("payload is valid JSON");
    assert!(
        payload.get("dry_run").is_none(),
        "enforce-mode audit entry must not carry dry_run"
    );
}

#[tokio::test]
async fn st_sandbox_4_per_agent_override_isolates_two_agents_under_one_policy() {
    // Per-agent override AC: two agents share the same deny policy. One
    // registers with EnforcementMode::Observe (experimental), the other
    // without an override (trusted, defaults to Enforce). Each must resolve
    // to its own mode independently on the request path.
    let (addr, registry, _audit_rx) = start_server_with_audit_rx(DENY_BASH_POLICY).await;

    let experimental_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "experimental-agent".into(),
    };
    let trusted_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "trusted-agent".into(),
    };
    register_agent_with_mode(
        &registry,
        "experimental-agent",
        &experimental_id,
        Some(aa_core::EnforcementMode::Observe),
    );
    register_agent_with_mode(&registry, "trusted-agent", &trusted_id, None);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let experimental_resp = client
        .check_action(tool_call_request_for(&experimental_id, "bash"))
        .await
        .unwrap()
        .into_inner();
    let trusted_resp = client
        .check_action(tool_call_request_for(&trusted_id, "bash"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        experimental_resp.decision,
        Decision::Allow as i32,
        "experimental agent in observe mode must proceed",
    );
    assert_eq!(
        trusted_resp.decision,
        Decision::Deny as i32,
        "trusted agent under same policy must still be blocked — got reason {:?}",
        trusted_resp.reason,
    );
}
