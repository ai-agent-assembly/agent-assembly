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
//! * **ST-org-3** — Cross-org budget isolation: `BudgetTracker` now holds an
//!   `org_budgets` map plus `with_org_daily_limit` / `with_org_monthly_limit`
//!   builders (AAASM-2022). Two orgs sharing the same per-org cap prove
//!   isolation: spending in org-alpha exhausts its envelope without affecting
//!   org-beta.
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
    let engine_inner = PolicyEngine::load_from_file(&path, alert_tx).expect("policy fixture loads");
    spawn_gateway_with_engine_builder(engine_inner).await
}

/// AAASM-2023 — companion helper that loads a directory of YAML documents
/// via `PolicyEngine::load_cascade_from_dir`. Used by the org-scoped ST-org-4
/// test where the gateway needs both a Global default and an Org-scoped rule.
async fn start_gateway_with_cascade_dir(
    policy_dir: &str,
) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let path = fixture_path(policy_dir);
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine_inner = PolicyEngine::load_cascade_from_dir(&path, alert_tx).expect("cascade fixture loads");
    spawn_gateway_with_engine_builder(engine_inner).await
}

/// Build the registry first, attach it to the engine via `with_registry`
/// (so `collect_cascade` can resolve `lineage.org_id`), then wire the gRPC
/// server. Returns the bound addr + registry handle + audit receiver.
async fn spawn_gateway_with_engine_builder(
    engine_inner: PolicyEngine,
) -> (SocketAddr, Arc<AgentRegistry>, mpsc::Receiver<AuditEntry>) {
    let registry = Arc::new(AgentRegistry::new());
    // AAASM-2023 — engine.with_registry is the key step: collect_cascade
    // walks `self.registry.lineage(agent_id)` for org/team scoping; without
    // it the cascade is collapsed to Global-only and org-scoped policies
    // never fire even when scope_index has them registered.
    let engine = Arc::new(engine_inner.with_registry(Arc::clone(&registry)));
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(engine, Arc::clone(&registry), audit_tx, audit_drops, [0u8; 32]);

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

#[test]
fn st_org_3_cross_org_budget_isolation() {
    // AAASM-2022 — exercises the Org tier on `BudgetTracker` directly.
    //
    // The check_action gRPC surface does not transport `cost_usd`, and there
    // is no production HTTP route for spend ingestion (same caveat documented
    // by the F116 ST-F suite in `e2e_budget.rs`). Driving the tracker
    // in-process gives the strongest assertion of the tier's semantics
    // without papering over the missing transport layer.
    use aa_core::AgentId;
    use aa_gateway::budget::pricing::PricingTable;
    use aa_gateway::budget::tracker::BudgetTracker;
    use aa_gateway::budget::types::BudgetStatus;
    use rust_decimal::Decimal;
    use std::str::FromStr;

    let cap = Decimal::from_str("1.00").expect("cap parses");
    let tracker =
        BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC).with_org_daily_limit(cap);

    let agent_alpha = AgentId::from_bytes([0xAA; 16]);
    let agent_beta = AgentId::from_bytes([0xBB; 16]);

    // org-alpha consumes the full envelope in two transactions.
    let first = tracker.record_raw_spend(agent_alpha, None, Some("org-alpha"), Decimal::from_str("0.60").unwrap());
    assert!(
        matches!(first, BudgetStatus::WithinBudget { .. }),
        "first org-alpha spend must be within budget, got {first:?}"
    );

    // Pushing org-alpha to the cap exactly trips the Org daily limit.
    let exhaust = tracker.record_raw_spend(agent_alpha, None, Some("org-alpha"), Decimal::from_str("0.40").unwrap());
    assert_eq!(
        exhaust,
        BudgetStatus::LimitExceeded,
        "org-alpha must trip its $1.00 daily envelope at exactly $1.00",
    );

    // org-beta has its own envelope — spending after org-alpha exhausted
    // must NOT be affected.
    let beta = tracker.record_raw_spend(agent_beta, None, Some("org-beta"), Decimal::from_str("0.50").unwrap());
    assert!(
        matches!(beta, BudgetStatus::WithinBudget { .. }),
        "org-beta must remain within budget despite org-alpha exhaustion, got {beta:?}"
    );

    // Tracker reports each org's spend independently.
    let alpha_state = tracker.org_state("org-alpha").expect("org-alpha must have a state");
    assert_eq!(alpha_state.spent_usd, cap, "org-alpha spend = $1.00");

    let beta_state = tracker.org_state("org-beta").expect("org-beta must have a state");
    assert_eq!(
        beta_state.spent_usd,
        Decimal::from_str("0.50").unwrap(),
        "org-beta spend = $0.50, isolated from org-alpha",
    );
}

// ── ST-org-4 ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn st_org_4_policy_with_org_scope_fires_only_for_matching_org() {
    // AAASM-2023 un-ignored this test. Uses the new
    // `PolicyEngine::load_cascade_from_dir` to load TWO policy documents
    // from a single directory:
    //
    //   policies/org_cascade/
    //   ├── 000-global-allow-all.yaml   (scope: global, empty tools)
    //   └── 100-org-alpha-deny-bash.yaml (scope: org:org-alpha, deny bash)
    //
    // Cascade collector at engine/mod.rs:1083-1116 walks the scopes for
    // each agent's lineage. Org-alpha agents include the org-alpha
    // document → bash is denied. Org-beta agents don't include it →
    // bash falls through to the Global allow-all default.
    let (addr, registry, _audit_rx) = start_gateway_with_cascade_dir("policies/org_cascade").await;

    let alpha = id("org-alpha", "team", "agent-a");
    let beta = id("org-beta", "team", "agent-b");
    register_agent(&registry, &alpha, "tok-alpha");
    register_agent(&registry, &beta, "tok-beta");

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // bash from org-alpha → Deny (the org-scoped policy fires).
    let alpha_resp = client
        .check_action(tool_call(&alpha, "tok-alpha", "bash", "t-alpha"))
        .await
        .expect("alpha bash")
        .into_inner();
    assert_eq!(
        alpha_resp.decision,
        Decision::Deny as i32,
        "org-alpha bash must be denied by the org-scoped policy (cascade includes org-alpha doc)"
    );

    // bash from org-beta → Allow (cascade for org-beta only includes the
    // Global allow-all default; the org-alpha-scoped doc is filtered out
    // by lineage.org_id mismatch).
    let beta_resp = client
        .check_action(tool_call(&beta, "tok-beta", "bash", "t-beta"))
        .await
        .expect("beta bash")
        .into_inner();
    assert_eq!(
        beta_resp.decision,
        Decision::Allow as i32,
        "org-beta bash must pass through — the org-alpha-scoped policy must not fire"
    );
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
