//! AAASM-3992 (completes AAASM-3416) — a tokenless `check_action` that claims a
//! tenant it cannot authenticate must NOT be trusted for budget attribution or
//! audit lineage. The request is NOT denied (that would break the normal OSS /
//! self-host runtime→gateway flow, where unregistered agents forward checks
//! without a per-agent credential token but with tenancy from their config);
//! instead the unauthenticated tenancy is NEUTRALIZED to an anonymous tenant.
//!
//! PolicyService runs under the non-rejecting `enrich` interceptor, so the
//! request-body `{org,team,agent}` triple and `credential_token` are
//! attacker-controlled. An unauthenticated peer at :50051 could send
//! `check_action` with an empty credential token, a novel *unregistered*
//! `{org,team,agent}` triple, and a client-chosen `org_id`. Because no
//! authoritative owner resolves, the gateway drops the client-supplied tenancy
//! so:
//!
//! * budget spend accrues to an anonymous tenant, NEVER the victim org/team; and
//! * the audit entry carries no victim org/team lineage.
//!
//! Policy evaluation still proceeds (global / default / tool-scoped rules apply),
//! so per-tool deny and global rules remain enforced. The registered-agent path
//! (valid token → registered owner tenancy) and untenanted requests are
//! unchanged.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, LlmCallContext, ToolCallContext};
use tonic::Request;

const ALLOW_ALL_POLICY: &str = r#"
version: "1"
tools:
  any_tool:
    allow: true
"#;

const REGISTERED_AGENT: &str = "legit-agent";
const REGISTERED_TOKEN: &str = "tok_legit";

const VICTIM_ORG: &str = "victim-org";
const VICTIM_TEAM: &str = "victim-team";

fn registered_record(agent_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: agent_key,
        name: "legit".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_legit".into(),
        credential_token: REGISTERED_TOKEN.into(),
        metadata: std::collections::BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: std::collections::VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        org_id: None,
    }
}

fn tool_request(agent: ProtoAgentId, token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent),
        credential_token: token.into(),
        trace_id: "trace".into(),
        span_id: "span".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "any_tool".into(),
                tool_source: "src".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

/// An `LLM_CALL` request that prices to $1.00 (gpt-4o, 200k prompt tokens) so
/// budget spend is actually accrued when the call is allowed.
fn llm_request(agent: ProtoAgentId, token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent),
        credential_token: token.into(),
        trace_id: "trace-llm".into(),
        span_id: "span-llm".into(),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: "gpt-4o".into(),
                prompt_tokens: 200_000,
                contains_pii: false,
            })),
        }),
        caller_agent_id: None,
    }
}

/// Build a service with a registered agent (so the registry is "attached" and
/// non-empty). Returns the service, the audit receiver, and the engine handle
/// (for budget inspection).
fn service() -> (
    Arc<PolicyServiceImpl>,
    tokio::sync::mpsc::Receiver<AuditEntry>,
    Arc<PolicyEngine>,
) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_ALL_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    // A registered agent makes the registry "attached" and non-empty.
    let key = proto_agent_id_to_key(&ProtoAgentId {
        org_id: "legit-org".into(),
        team_id: "legit-team".into(),
        agent_id: REGISTERED_AGENT.into(),
    });
    registry.register(registered_record(key)).unwrap();

    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(Arc::clone(&engine), registry, audit_tx, audit_drops, [0u8; 32]);
    (Arc::new(service), audit_rx, engine)
}

#[tokio::test]
async fn empty_token_unregistered_with_tenancy_claim_is_evaluated_not_denied() {
    let (service, _audit_rx, _engine) = service();

    // Attacker: empty token, an unregistered triple, but a client-chosen org/team.
    let attacker = ProtoAgentId {
        org_id: VICTIM_ORG.into(),
        team_id: VICTIM_TEAM.into(),
        agent_id: "novel-unregistered".into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(attacker, "")))
        .await
        .expect("check_action returns a response")
        .into_inner();

    // The request is NOT rejected — policy evaluation proceeds (allow-all here),
    // exactly as a request that carries no tenancy claim at all behaves.
    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "an unauthenticated-tenancy request must still be evaluated, not denied",
    );
}

#[tokio::test]
async fn unauthenticated_tenancy_does_not_mutate_victim_budget() {
    let (service, _audit_rx, engine) = service();

    // Attacker: empty token, unregistered, claiming the victim's org/team, and an
    // LLM call that would accrue $1.00 of spend.
    let attacker = ProtoAgentId {
        org_id: VICTIM_ORG.into(),
        team_id: VICTIM_TEAM.into(),
        agent_id: "novel-unregistered".into(),
    };
    let resp = service
        .check_action(Request::new(llm_request(attacker, "")))
        .await
        .expect("check_action returns a response")
        .into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32, "allow-all evaluation");

    // The vulnerability closed: spend must NOT be attributed to the victim tenant.
    let budget = engine.budget_tracker();
    assert!(
        budget.team_state(VICTIM_TEAM).is_none(),
        "spend must NOT accrue against the client-claimed victim team",
    );
    assert!(
        budget.org_state(VICTIM_ORG).is_none(),
        "spend must NOT accrue against the client-claimed victim org",
    );
}

#[tokio::test]
async fn unauthenticated_tenancy_does_not_forge_victim_audit_lineage() {
    let (service, mut audit_rx, _engine) = service();

    let attacker = ProtoAgentId {
        org_id: VICTIM_ORG.into(),
        team_id: VICTIM_TEAM.into(),
        agent_id: "novel-unregistered".into(),
    };
    service
        .check_action(Request::new(tool_request(attacker, "")))
        .await
        .expect("check_action returns a response");

    // An audit entry is written for the evaluated action, but it must NOT carry
    // the client-claimed victim tenancy in its lineage — the attacker cannot
    // forge audit entries under a victim tenant.
    let entry = audit_rx
        .recv()
        .await
        .expect("an audit entry is written for the evaluated action");
    assert_ne!(
        entry.org_id(),
        Some(VICTIM_ORG),
        "the audit entry must not be attributed to the client-claimed victim org",
    );
    assert_ne!(
        entry.team_id(),
        Some(VICTIM_TEAM),
        "the audit entry must not be attributed to the client-claimed victim team",
    );
}

#[tokio::test]
async fn registered_agent_with_valid_token_still_allowed() {
    let (service, _audit_rx, _engine) = service();

    let legit = ProtoAgentId {
        org_id: "legit-org".into(),
        team_id: "legit-team".into(),
        agent_id: REGISTERED_AGENT.into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(legit, REGISTERED_TOKEN)))
        .await
        .expect("check_action returns a response")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "the legitimate registered-agent path must be unaffected",
    );
}

#[tokio::test]
async fn empty_token_unregistered_without_tenancy_claim_passes_through() {
    let (service, _audit_rx, _engine) = service();

    // No org/team claim: the lightweight untenanted / unregistered-deployment
    // path. This must be evaluated normally (and is the behaviour the
    // unauthenticated-tenancy case is neutralized to match).
    let untenanted = ProtoAgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "untenanted".into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(untenanted, "")))
        .await
        .expect("check_action returns a response")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "an untenanted tokenless request must still be evaluated normally",
    );
}
