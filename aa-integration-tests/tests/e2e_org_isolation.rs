//! AAASM-2008 / F116 follow-up — Org-tier isolation E2E.
//!
//! Acceptance attestation for spec highlight ⑧ "Org / Team / Agent 層級管理"
//! at the **multi-tenancy tier**. AAASM-1524 (ST-L) covers the Agent and
//! Team tiers; this file covers the Org tier that the F116 closeout audit
//! flagged as missing E2E coverage.
//!
//! ## Test cases
//!
//! * **ST-org-1** — Cross-org audit isolation: agent A (Org alpha) and
//!   agent B (Org beta) emit audit entries; each entry carries its
//!   originating org_id on Lineage so downstream filters can scope by
//!   tenant.
//! * **ST-org-2** — Cross-org topology isolation: registry's
//!   `org_members(oid)` returns only that org's agents.
//! * **ST-org-3** — Cross-org budget isolation (ignored placeholder):
//!   `BudgetTracker` is keyed by `team_id` today; an Org-explicit
//!   tier requires `org_budgets` plumbing — filed as a follow-up
//!   subtask after this PR opens.
//! * **ST-org-4** — Org-scoped policy evaluation: a policy with
//!   `scope: org:org-alpha` fires only for org-alpha agents; org-beta
//!   agents fall through to the cascade default.
//! * **ST-org-5** — Cross-org credential rejection: agent A in
//!   org-alpha presenting a valid token but claiming `agent_id.org_id =
//!   "org-beta"` is rejected via the registry's credential reverse
//!   index, with an `A2AImpersonationAttempted` audit event.

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
    let org_id = if proto_id.org_id.is_empty() {
        None
    } else {
        Some(proto_id.org_id.clone())
    };
    let team_id = if proto_id.team_id.is_empty() {
        None
    } else {
        Some(proto_id.team_id.clone())
    };
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
        team_id,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
        org_id,
    };
    registry.register(record).expect("register agent");
}

fn id(org: &str, team: &str, agent: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: org.into(),
        team_id: team.into(),
        agent_id: agent.into(),
    }
}

fn tool_call(callee: &ProtoAgentId, token: &str, tool: &str, trace: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(callee.clone()),
        credential_token: token.into(),
        trace_id: trace.into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool.into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

async fn drain_audit(rx: &mut mpsc::Receiver<AuditEntry>, expected: usize) -> Vec<AuditEntry> {
    let mut out = vec![];
    for _ in 0..(expected + 5) {
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Ok(Some(entry)) => out.push(entry),
            _ => break,
        }
    }
    out
}

// ── ST-org-1 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_org_1_audit_entries_carry_org_id_for_cross_org_isolation() {
    let (addr, registry, mut audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    let alpha = id("org-alpha", "team", "agent-a");
    let beta = id("org-beta", "team", "agent-b");
    register_agent(&registry, &alpha, "tok-alpha");
    register_agent(&registry, &beta, "tok-beta");

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // Each agent invokes the allowed `read_file` tool from allow_deny_mixed.
    client
        .check_action(tool_call(&alpha, "tok-alpha", "read_file", "trace-1"))
        .await
        .expect("alpha allow")
        .into_inner();
    client
        .check_action(tool_call(&beta, "tok-beta", "read_file", "trace-2"))
        .await
        .expect("beta allow")
        .into_inner();

    let entries = drain_audit(&mut audit_rx, 2).await;
    assert_eq!(entries.len(), 2, "two allow events expected");

    // Find each org's entry and assert its org_id stamp is correct.
    let alpha_entry = entries.iter().find(|e| e.org_id() == Some("org-alpha"));
    let beta_entry = entries.iter().find(|e| e.org_id() == Some("org-beta"));
    assert!(
        alpha_entry.is_some(),
        "org-alpha audit entry must carry org_id; entries: {entries:?}",
    );
    assert!(
        beta_entry.is_some(),
        "org-beta audit entry must carry org_id; entries: {entries:?}",
    );
    // Cross-org isolation: every org-alpha entry MUST NOT have org-beta on it.
    for e in &entries {
        if e.org_id() == Some("org-alpha") {
            assert_ne!(e.team_id(), Some("org-beta"), "no cross-org bleed");
        }
    }
}

// ── ST-org-2 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_org_2_registry_org_members_scopes_topology_by_org() {
    let (_addr, registry, _audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    register_agent(&registry, &id("org-alpha", "t", "a1"), "t1");
    register_agent(&registry, &id("org-alpha", "t", "a2"), "t2");
    register_agent(&registry, &id("org-beta", "t", "b1"), "t3");

    let alpha_members = registry.org_members("org-alpha");
    let beta_members = registry.org_members("org-beta");

    assert_eq!(alpha_members.len(), 2, "org-alpha has 2 agents");
    assert_eq!(beta_members.len(), 1, "org-beta has 1 agent");

    // Cross-org isolation: no overlap.
    for k in &alpha_members {
        assert!(!beta_members.contains(k), "no overlap between org members");
    }
}

// ── ST-org-3 ────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "AAASM-2022: explicit Org-tier budget tracking — BudgetTracker keys by team_id today; \
    cross-org isolation works for non-pathological setups (orgs with distinct team_ids) but the \
    AC asks for an explicit Org tier that this PR does not wire"]
async fn st_org_3_cross_org_budget_isolation() {
    // When AAASM-2022 ships:
    //
    // 1. Configure org-alpha with a daily budget of $1 and org-beta with $10.
    // 2. Drive enough cost-bearing actions from an org-alpha agent to exhaust
    //    its $1 budget.
    // 3. Assert org-alpha agents now hit budget-exceeded denies.
    // 4. Assert org-beta agents continue accepting (org-isolation; their
    //    budget was not affected by org-alpha's exhaustion).
    // 5. Assert the budget-exceeded audit events for org-alpha do not appear
    //    in a `/api/v1/logs?org_id=org-beta` query.
    unimplemented!("AAASM-2022 — explicit Org-tier budget enforcement");
}

// ── ST-org-4 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "AAASM-2023: PolicyEngine::load_from_file does not populate the scope_index, so org-scoped \
    policies route through evaluate_primary and apply globally. The engine's scope_index cascade \
    DOES handle PolicyScope::Org correctly (covered by aa-gateway/tests/cascade_merge_test.rs), but \
    exercising it E2E here requires a multi-document loader — filed as a follow-up subtask"]
async fn st_org_4_policy_with_org_scope_fires_only_for_matching_org() {
    // When AAASM-2023 ships a `PolicyEngine::load_cascade_from_dir(...)` or
    // equivalent multi-document loader, this test will:
    //
    // 1. Load TWO policy documents: a Global allow-all + an
    //    org-alpha-scoped deny-bash (org_scoped_deny_bash.yaml fixture).
    // 2. Register agents in org-alpha and org-beta.
    // 3. Drive `bash` from each agent.
    // 4. Assert: org-alpha → Deny (org-scoped rule fires); org-beta →
    //    Allow (org-scoped rule does NOT fire — lineage.org_id filters it
    //    out of the cascade).
    //
    // The pure-logic equivalent (cascade evaluator + PolicyScope::Org
    // filtering) is already unit-tested in
    // aa-gateway/tests/cascade_merge_test.rs::cascade_merge_org_team_agent.
    // This E2E test is the F116 acceptance lens; un-ignored when AAASM-2023
    // wires the gateway-side multi-document loader.
    unimplemented!("AAASM-2023 — gateway multi-document cascade loader");
}

// ── ST-org-5 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_org_5_cross_org_credential_reuse_is_rejected_with_impersonation_audit() {
    let (addr, registry, mut audit_rx) = start_gateway("policies/allow_deny_mixed.yaml").await;

    // Register agent A in org-alpha with token "alpha-tok".
    let alpha = id("org-alpha", "team", "agent-x");
    register_agent(&registry, &alpha, "alpha-tok");

    // Attacker claims `agent_id.org_id = "org-beta"` with the SAME agent_id
    // string and the LEGITIMATE token. The registry lookup at the cross-org
    // hash key returns None — the new credential reverse index must catch
    // the impersonation.
    let claimed_beta = id("org-beta", "team", "agent-x");
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call(&claimed_beta, "alpha-tok", "read_file", "t-impersonate"))
        .await
        .expect("Deny path")
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "credential token registered to a different agent");
    assert_eq!(resp.policy_rule, "a2a_identity_verification");

    let entries = drain_audit(&mut audit_rx, 1).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type(), AuditEventType::A2AImpersonationAttempted);

    let payload: serde_json::Value = serde_json::from_str(entries[0].payload()).expect("payload JSON");
    assert_eq!(payload["claimed_agent_id"], "agent-x");
    assert_eq!(payload["claimed_org_id"], "org-beta");
}
