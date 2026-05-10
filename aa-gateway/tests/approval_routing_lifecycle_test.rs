//! Integration test for the full team-approval-routing lifecycle.
//!
//! Covers AC6: route to team → no action → timer fires → escalate to OrgAdmin → approve;
//! asserts state transitions, routing-status updates, and that the correct routing and
//! escalation events are produced.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use uuid::Uuid;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, ApprovalKind, GovernanceLevel, PolicyResult};
use aa_gateway::approval::audit_sink::NoopAuditSink;
use aa_gateway::approval::clock::FakeClock;
use aa_gateway::approval::escalation::EscalationScheduler;
use aa_gateway::approval::repo::ApprovalRoutingRepo;
use aa_gateway::approval::router::ApprovalRouter;
use aa_gateway::approval::routing_config::{RoutingConfigStore, TeamRoutingConfig};
use aa_gateway::approval::sqlite_repo::SqliteApprovalRoutingRepo;
use aa_runtime::approval::{ApprovalDecision, ApprovalQueue, ApprovalRequest};
use sqlx::SqlitePool;

// ── helpers ────────────────────────────────────────────────────────────────────

fn temp_path(suffix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("routing_lifecycle_{}_{}.json", suffix, Uuid::new_v4()));
    p
}

fn make_request(team_id: Option<&str>) -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "agent-1".to_string(),
        action: "delete_production_db".to_string(),
        condition_triggered: "requires_approval".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 300,
        fallback: PolicyResult::Deny {
            reason: "approval timed out".to_string(),
        },
        team_id: team_id.map(str::to_string),
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

fn make_ctx(team_id: Option<&str>) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([0u8; 16]),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 1,
        started_at: Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: team_id.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

async fn in_memory_repo() -> SqliteApprovalRoutingRepo {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    SqliteApprovalRoutingRepo::new(pool).await.unwrap()
}

fn router_with_repo(repo: SqliteApprovalRoutingRepo, now_secs: u64) -> ApprovalRouter {
    ApprovalRouter::new(
        Arc::new(repo),
        Arc::new(NoopAuditSink),
        Arc::new(FakeClock::new(now_secs)),
    )
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn router_resolves_team_and_approvers() {
    let repo = in_memory_repo().await;
    repo.upsert(TeamRoutingConfig {
        team_id: "team-alpha".to_string(),
        approvers: vec!["alice".to_string(), "bob".to_string()],
        escalation_timeout_secs: 1800,
        escalation_approvers: vec!["org-admin".to_string()],
        approval_kind: None,
    })
    .await
    .unwrap();

    let router = router_with_repo(repo, 0);
    let req = make_request(Some("team-alpha"));
    let ctx = make_ctx(Some("team-alpha"));

    let decision = router.route(&req, &ctx).await.unwrap();

    assert_eq!(decision.team_id, Some("team-alpha".to_string()));
    assert_eq!(decision.target_role, "TeamAdmin");
    assert_eq!(decision.escalation_role, "org-admin");
    assert_eq!(decision.escalate_at, 1800);
}

#[tokio::test]
async fn router_no_team_id_returns_org_admin() {
    let repo = in_memory_repo().await;
    let router = router_with_repo(repo, 0);
    let req = make_request(None);
    let ctx = make_ctx(None);

    let decision = router.route(&req, &ctx).await.unwrap();

    assert_eq!(decision.team_id, None);
    assert_eq!(decision.target_role, "OrgAdmin");
}

#[tokio::test]
async fn router_unknown_team_uses_global_default() {
    let repo = in_memory_repo().await;
    let router = router_with_repo(repo, 0);
    let req = make_request(Some("team-not-configured"));
    let ctx = make_ctx(Some("team-not-configured"));

    let decision = router.route(&req, &ctx).await.unwrap();

    assert_eq!(decision.team_id, Some("team-not-configured".to_string()));
    assert_eq!(decision.target_role, "TeamAdmin");
    assert_eq!(decision.escalation_role, "OrgAdmin"); // global default
}

#[test]
fn routing_config_preserves_approval_kind() {
    let store_path = temp_path("approval_kind");
    let mut store = RoutingConfigStore::load(&store_path).unwrap();
    store
        .upsert(TeamRoutingConfig {
            team_id: "team-beta".to_string(),
            approvers: vec!["carol".to_string()],
            escalation_timeout_secs: 600,
            escalation_approvers: vec!["org-admin".to_string()],
            approval_kind: Some(ApprovalKind::ToolUse),
        })
        .unwrap();
    let cfg = store.get("team-beta").unwrap();
    assert_eq!(cfg.approval_kind, Some(ApprovalKind::ToolUse));
    let _ = std::fs::remove_file(&store_path);
}

#[tokio::test]
async fn full_lifecycle_route_escalate_approve() {
    // 1. Routing config: team-x with immediate escalation
    let repo = in_memory_repo().await;
    repo.upsert(TeamRoutingConfig {
        team_id: "team-x".to_string(),
        approvers: vec!["alice".to_string()],
        escalation_timeout_secs: 0, // fires immediately
        escalation_approvers: vec!["org-admin".to_string()],
        approval_kind: None,
    })
    .await
    .unwrap();

    // 2. Route the request
    let router = router_with_repo(repo, 0);
    let req = make_request(Some("team-x"));
    let ctx = make_ctx(Some("team-x"));
    let request_id = req.request_id;

    let routing_decision = router.route(&req, &ctx).await.unwrap();
    assert_eq!(routing_decision.team_id, Some("team-x".to_string()));
    let escalation_timeout = routing_decision.escalate_at; // now (0) + 0 = 0

    // 3. Submit to approval queue
    let queue = ApprovalQueue::new();
    let (_id, decision_future) = queue.submit(req);

    // AC2: production code calls update_routing_status("routed_to_team_admin") after submit.
    queue.update_routing_status(request_id, "routed_to_team_admin".to_string());

    let pending = queue.list();
    let entry = pending.iter().find(|p| p.request_id == request_id).unwrap();
    assert_eq!(
        entry.routing_status.as_deref(),
        Some("routed_to_team_admin"),
        "routing_status must be set to routed_to_team_admin immediately after routing"
    );

    // 4. Register with escalation scheduler
    let escalation_path = temp_path("lifecycle_escalation");
    let (escalation_tx, mut escalation_rx) = broadcast::channel(16);
    let scheduler =
        Arc::new(EscalationScheduler::new(&escalation_path, escalation_tx, Duration::from_millis(50)).unwrap());
    scheduler
        .register(
            request_id,
            "team-x".to_string(),
            vec!["org-admin".to_string()],
            escalation_timeout,
        )
        .unwrap();

    // 5. Tick → escalation fires (timeout was 0)
    scheduler.tick();
    let event = escalation_rx.try_recv().expect("escalation event must fire");
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.team_id, "team-x");
    assert_eq!(event.escalation_approvers, vec!["org-admin"]);

    // 5b. Simulate routing_status update on the queue.
    let to_role = event.escalation_approvers.join(",");
    queue.update_routing_status(request_id, format!("escalated:{to_role}"));

    let pending = queue.list();
    let entry = pending.iter().find(|p| p.request_id == request_id).unwrap();
    assert_eq!(
        entry.routing_status.as_deref(),
        Some("escalated:org-admin"),
        "routing_status must reflect escalation before decision"
    );

    // 6. Org admin approves
    queue
        .decide(
            request_id,
            ApprovalDecision::Approved {
                by: "org-admin".to_string(),
                reason: Some("escalated approval granted".to_string()),
            },
        )
        .unwrap();

    // 7. Decision future resolves
    let decision = tokio::time::timeout(Duration::from_secs(1), decision_future)
        .await
        .expect("future must resolve within 1s")
        .expect("channel must not be closed");

    assert!(
        matches!(decision, ApprovalDecision::Approved { .. }),
        "expected Approved, got {decision:?}"
    );

    // 8. Resolved request no longer appears in pending list.
    let pending = queue.list();
    assert!(
        pending.iter().all(|p| p.request_id != request_id),
        "resolved request must not appear in pending list"
    );

    let _ = std::fs::remove_file(&escalation_path);
}
