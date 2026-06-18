//! AAASM-3377 — full delegation lineage in the PERSISTED audit `payload`.
//!
//! Regression: a child agent's CheckAction lineage (root / parent / depth /
//! delegation_reason / spawned_by_tool) was carried only on the top-level
//! `AuditEntry` fields. Consumers that read the inner `payload` JSON never saw
//! the delegation chain. The earlier in-memory-struct test passed while the
//! persisted `payload` was still empty, so this test drives the *real persist
//! path*: it wires the live `AuditWriter` to a temp JSONL file, runs a
//! CheckAction for a depth-1 child, then reads the JSONL back and asserts the
//! lineage fields are present inside the persisted `payload`.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::audit::AuditWriter;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, LlmCallContext};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::Request;

const ALLOW_ALL_YAML: &str = "version: \"1\"\n";

/// Mirror `registry::convert::proto_agent_id_to_key` so the registered record
/// is keyed the same way the service looks it up.
fn key_for(org: &str, team: &str, agent: &str) -> [u8; 16] {
    let composite = format!("{org}/{team}/{agent}");
    let digest = Sha256::digest(composite.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn child_record(key: [u8; 16], parent_key: [u8; 16], root_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: key,
        name: "child".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: "child-token".into(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: Some("parent".into()),
        team_id: Some("team".into()),
        depth: 1,
        delegation_reason: Some("summarise results".into()),
        spawned_by_tool: Some("langgraph.subgraph".into()),
        root_agent_id: Some(root_key),
        children: vec![],
        parent_key: Some(parent_key),
        enforcement_mode: None,
        org_id: Some("org".into()),
    }
}

fn llm_request() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "child".into(),
        }),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: "gpt-4o".into(),
                prompt_tokens: 10,
                contains_pii: false,
            })),
        }),
        trace_id: "trace-lineage".into(),
        span_id: "span-lineage".into(),
        credential_token: "child-token".into(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn persisted_jsonl_payload_carries_full_lineage() {
    let registry = Arc::new(AgentRegistry::new());

    let parent_key = key_for("org", "team", "parent");
    let child_key = key_for("org", "team", "child");
    let root_key = parent_key; // depth-1 child: parent is the root.

    registry
        .register(child_record(child_key, parent_key, root_key))
        .expect("register child");

    // Wire the *real* AuditWriter to a temp JSONL file — this is the persist
    // path that QA inspects, not an in-memory struct check.
    let audit_dir = tempfile::tempdir().expect("tempdir");
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(16);
    let writer = AuditWriter::new(audit_dir.path().to_path_buf(), "org", "sess", audit_rx)
        .await
        .expect("audit writer");
    let writer_handle = tokio::spawn(writer.run());

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_ALL_YAML).unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(Arc::new(engine), registry, audit_tx, audit_drops, [0u8; 32]);

    service
        .check_action(Request::new(llm_request()))
        .await
        .expect("check_action ok");

    // Drop the service so its `audit_tx` closes; the writer then flushes and exits.
    drop(service);
    writer_handle.await.expect("writer task join");

    let jsonl_path = audit_dir.path().join("org-sess.jsonl");
    let content = std::fs::read_to_string(&jsonl_path).expect("read persisted jsonl");
    let line = content.trim();
    assert!(!line.is_empty(), "persisted JSONL must not be empty");

    let entry: serde_json::Value = serde_json::from_str(line).expect("parse persisted entry");
    let payload_str = entry
        .get("payload")
        .and_then(|p| p.as_str())
        .expect("persisted entry has a payload string");
    let payload: serde_json::Value = serde_json::from_str(payload_str).expect("parse persisted payload");

    assert_eq!(payload["org_id"], "org", "org_id persisted in payload");
    assert_eq!(payload["team_id"], "team", "team_id persisted in payload");
    assert_eq!(
        payload["root_agent_id"],
        serde_json::json!(hex::encode(root_key)),
        "root_agent_id persisted in payload"
    );
    assert_eq!(
        payload["parent_agent_id"],
        serde_json::json!(hex::encode(parent_key)),
        "parent_agent_id persisted in payload"
    );
    assert_eq!(payload["depth"], 1, "depth persisted in payload");
    assert_eq!(
        payload["delegation_reason"], "summarise results",
        "delegation_reason persisted in payload"
    );
    assert_eq!(
        payload["spawned_by_tool"], "langgraph.subgraph",
        "spawned_by_tool persisted in payload"
    );
}
