//! AAASM-3751 — cross-tenant policy-downgrade regression at the service layer.
//!
//! Root cause: the agent registry is keyed by the COMPOSITE key
//! `proto_agent_id_to_key` = `SHA256("{org_id}/{team_id}/{agent_id}")[..16]`,
//! but the engine's `authoritative_lineage` / `authoritative_tenancy` look the
//! registered owner up by `ctx.agent_id.as_bytes()` — the BARE
//! `hash_to_16(agent_id)` produced by `convert::request_to_core`. Bare never
//! equals composite, so the registry lookup inside the engine always misses
//! and the cascade falls back to the CLIENT-supplied `ctx.metadata["org_id"]`.
//! A caller can therefore forge `org_id` to point evaluation at a more
//! permissive org's policy and downgrade the deny that actually applies.
//!
//! Fix: `evaluate_one` already resolves the record by the composite key (to set
//! `governance_level`); it now also deposits the registered owner's `org_id` /
//! `team_id` into `ctx`, overwriting any client-supplied values, so the engine's
//! ctx-fallback resolves to the authoritative owner.
//!
//! Why the record below stores `org_id = "owner-org"` while it is keyed under a
//! proto carrying `org_id = "forged-permissive-org"`: in production a record's
//! stored `org_id` always equals the org embedded in its own composite key, so
//! for a self-consistent agent the client-claimed org and the registered org
//! coincide and the bug cannot be observed. To isolate "registered owner" from
//! "client-supplied lineage" we plant the divergence directly — exactly as the
//! engine-level `cascade_uses_registered_org_not_client_forged_org` test does
//! with a bare key. The request resolves to the record by composite key; the
//! authoritative `org_id` stored on the record is what must win.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::GovernanceLevel;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;

/// Global allow-all + an org-scoped deny for `owner-org`'s `bash`.
fn write_cascade(dir: &std::path::Path) {
    std::fs::write(
        dir.join("000-global-allow-all.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: t-global-allow\n  version: \"0.1.0\"\n\
         spec:\n  tools: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("100-org-owner-deny-bash.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: t-owner-deny-bash\n  version: \"0.1.0\"\n\
         spec:\n  scope: org:owner-org\n  tools:\n    bash:\n      allow: false\n",
    )
    .unwrap();
}

/// Build a service whose engine loads the org-scoped cascade and whose registry
/// is shared with the engine (production parity).
fn build_service(dir: &std::path::Path) -> (PolicyServiceImpl, Arc<AgentRegistry>) {
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let registry = Arc::new(AgentRegistry::new());
    let engine = Arc::new(
        PolicyEngine::load_cascade_from_dir(dir, alert_tx)
            .expect("cascade loads")
            .with_registry(Arc::clone(&registry)),
    );
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let service = PolicyServiceImpl::with_registry(
        engine,
        Arc::clone(&registry),
        audit_tx,
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    );
    (service, registry)
}

/// Register an agent under the composite key derived from `proto_id`, but store
/// `record_org` as its authoritative owner org.
fn register_owned_by(
    registry: &AgentRegistry,
    proto_id: &ProtoAgentId,
    record_org: Option<&str>,
    record_team: Option<&str>,
) {
    let key = proto_agent_id_to_key(proto_id);
    let record = AgentRecord {
        agent_id: key,
        name: "demo".into(),
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
        team_id: record_team.map(str::to_string),
        org_id: record_org.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
    };
    registry.register(record).unwrap();
}

fn bash_request(proto_id: &ProtoAgentId) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_id.clone()),
        credential_token: "tok".into(),
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "bash".into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn forged_org_cannot_downgrade_to_permissive_cascade() {
    // `_tmp` keeps the cascade directory alive for the whole test so the live
    // watcher never re-reads a deleted dir mid-evaluate (AAASM-3729).
    let _tmp = tempfile::tempdir().unwrap();
    write_cascade(_tmp.path());
    let (service, registry) = build_service(_tmp.path());

    // Client claims the permissive org; the agent's *registered* owner is the
    // restrictive `owner-org`, which denies `bash`.
    let proto_id = ProtoAgentId {
        org_id: "forged-permissive-org".into(),
        team_id: "owner-team".into(),
        agent_id: "agent-1".into(),
    };
    register_owned_by(&registry, &proto_id, Some("owner-org"), Some("owner-team"));

    let resp = service
        .check_action(tonic::Request::new(bash_request(&proto_id)))
        .await
        .unwrap()
        .into_inner();

    // Without the evaluate_one deposit the engine falls back to the forged
    // `forged-permissive-org` (no deny rule) and returns Allow. With the fix the
    // registered `owner-org` deny applies.
    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "registered owner-org deny must apply despite the client-forged org_id (got reason: {})",
        resp.reason
    );
}

#[tokio::test]
async fn registered_permissive_org_is_allowed() {
    // Sanity / inverse: an agent whose registered owner really is a permissive
    // org (no deny rule) is allowed — proving the deny above is driven by the
    // registered owner, not by some unrelated default.
    let _tmp = tempfile::tempdir().unwrap();
    write_cascade(_tmp.path());
    let (service, registry) = build_service(_tmp.path());

    let proto_id = ProtoAgentId {
        org_id: "owner-org".into(),
        team_id: "owner-team".into(),
        agent_id: "agent-2".into(),
    };
    register_owned_by(&registry, &proto_id, Some("permissive-org"), Some("owner-team"));

    let resp = service
        .check_action(tonic::Request::new(bash_request(&proto_id)))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "registered permissive-org owner has no deny rule and must be allowed (got reason: {})",
        resp.reason
    );
}
