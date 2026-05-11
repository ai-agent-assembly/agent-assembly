//! Integration test for the full team-approval-routing lifecycle.
//!
//! Covers AC6: route to team → no action → timer fires → escalate to OrgAdmin → approve;
//! asserts state transitions, routing-status updates, and that the correct routing and
//! escalation events are produced.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::broadcast;
use uuid::Uuid;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, ApprovalKind, AuditEventType, GovernanceLevel, PolicyResult};
use aa_gateway::approval::audit_sink::{AuditEventSink, NoopAuditSink};
use aa_gateway::approval::clock::{Clock, FakeClock};
use aa_gateway::approval::db_escalation_scheduler::DbEscalationScheduler;
use aa_gateway::approval::escalation::EscalationScheduler;
use aa_gateway::approval::repo::ApprovalRoutingRepo;
use aa_gateway::approval::router::ApprovalRouter;
use aa_gateway::approval::routing_config::{RoutingConfigStore, TeamRoutingConfig};
use aa_gateway::approval::sqlite_repo::SqliteApprovalRoutingRepo;
use aa_runtime::approval::{ApprovalDecision, ApprovalQueue, ApprovalRequest};
use sqlx::SqlitePool;

// ── helpers ────────────────────────────────────────────────────────────────────

/// Test-only audit sink that captures every emitted event for assertion.
struct RecordingAuditSink {
    events: Mutex<Vec<AuditEventType>>,
}

impl RecordingAuditSink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
        })
    }

    fn has(&self, event_type: AuditEventType) -> bool {
        self.events.lock().unwrap().contains(&event_type)
    }
}

impl AuditEventSink for RecordingAuditSink {
    fn emit(&self, event_type: AuditEventType, _payload: String) {
        self.events.lock().unwrap().push(event_type);
    }
}

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

#[tokio::test]
async fn full_lifecycle_with_db_scheduler_and_fake_clock() {
    // 1. Routing config: team-y escalates after 30s
    let repo = in_memory_repo().await;
    repo.upsert(TeamRoutingConfig {
        team_id: "team-y".to_string(),
        approvers: vec!["alice".to_string()],
        escalation_timeout_secs: 30,
        escalation_approvers: vec!["org-admin".to_string()],
        approval_kind: None,
    })
    .await
    .unwrap();

    // 2. Route at t=0 → escalate_at = 30
    let fake_clock = Arc::new(FakeClock::new(0));
    let audit_sink = RecordingAuditSink::new();
    let router = ApprovalRouter::new(
        Arc::new(repo),
        Arc::clone(&audit_sink) as Arc<dyn AuditEventSink>,
        fake_clock.clone() as Arc<dyn Clock>,
    );
    let req = make_request(Some("team-y"));
    let ctx = make_ctx(Some("team-y"));
    let request_id = req.request_id;
    let routing_decision = router.route(&req, &ctx).await.unwrap();
    assert_eq!(routing_decision.escalate_at, 30);

    // ApprovalRouted audit event must be emitted by the router
    assert!(
        audit_sink.has(AuditEventType::ApprovalRouted),
        "AuditEvent::ApprovalRouted must be emitted after routing"
    );

    // 3. Submit to queue
    let queue = ApprovalQueue::new();
    let (_id, decision_future) = queue.submit(req);
    queue.update_routing_status(request_id, "routed_to_team_admin".to_string());

    // 4. Create DbEscalationScheduler sharing the same fake_clock and audit sink
    let scheduler_pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    let check_pool = scheduler_pool.clone();
    let (escalation_tx, mut escalation_rx) = broadcast::channel(16);
    let scheduler = DbEscalationScheduler::new(
        scheduler_pool,
        fake_clock.clone() as Arc<dyn Clock>,
        Arc::clone(&queue),
        Arc::clone(&audit_sink) as Arc<dyn AuditEventSink>,
        escalation_tx,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // 5. Register escalation timer
    scheduler
        .register(
            request_id,
            "team-y".to_string(),
            "org-admin".to_string(),
            "TeamAdmin".to_string(),
            routing_decision.escalate_at,
        )
        .await
        .unwrap();

    // 6. Row must be present in pending_escalations
    let id_str = request_id.to_string();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_escalations WHERE approval_id = ?")
        .bind(&id_str)
        .fetch_one(&check_pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "pending_escalations row must exist after register");

    // 7. Tick at t=0 → nothing fires yet (escalate_at=30 > now=0)
    scheduler.tick().await.unwrap();
    assert!(
        escalation_rx.try_recv().is_err(),
        "no event must fire before escalate_at"
    );

    // 8. Advance clock to t=31 → escalation fires
    fake_clock.set(31);
    scheduler.tick().await.unwrap();
    let event = escalation_rx
        .try_recv()
        .expect("escalation event must fire after deadline");
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.team_id, "team-y");
    assert_eq!(event.escalation_approvers, vec!["org-admin"]);

    // ApprovalEscalated audit event must be emitted by the scheduler
    assert!(
        audit_sink.has(AuditEventType::ApprovalEscalated),
        "AuditEvent::ApprovalEscalated must be emitted after escalation fires"
    );

    // routing_status must be updated to reflect escalation
    let pending = queue.list();
    let entry = pending.iter().find(|p| p.request_id == request_id).unwrap();
    assert_eq!(
        entry.routing_status.as_deref(),
        Some("escalated_to_org-admin"),
        "routing_status must be escalated_to_<role> after escalation fires"
    );

    // 9. Row must be deleted from DB after escalation
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_escalations WHERE approval_id = ?")
        .bind(&id_str)
        .fetch_one(&check_pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "pending_escalations row must be deleted after fire");

    // 10. Org admin approves → future resolves
    queue
        .decide(
            request_id,
            ApprovalDecision::Approved {
                by: "org-admin".to_string(),
                reason: Some("escalated approval".to_string()),
            },
        )
        .unwrap();
    let decision = tokio::time::timeout(Duration::from_secs(1), decision_future)
        .await
        .expect("future must resolve within 1s")
        .expect("channel must not be closed");
    assert!(
        matches!(decision, ApprovalDecision::Approved { .. }),
        "expected Approved, got {decision:?}"
    );
    assert!(
        queue.list().iter().all(|p| p.request_id != request_id),
        "resolved request must not appear in pending list"
    );
}

#[tokio::test]
async fn negative_case_team_admin_approves_before_escalation() {
    let fake_clock = Arc::new(FakeClock::new(0));
    let queue = ApprovalQueue::new();

    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    let check_pool = pool.clone();
    let (escalation_tx, mut escalation_rx) = broadcast::channel(16);
    let scheduler = DbEscalationScheduler::new(
        pool,
        fake_clock.clone() as Arc<dyn Clock>,
        Arc::clone(&queue),
        Arc::new(NoopAuditSink),
        escalation_tx,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // Submit request and register an escalation far in the future
    let req = make_request(Some("team-z"));
    let request_id = req.request_id;
    let (_id, decision_future) = queue.submit(req);
    queue.update_routing_status(request_id, "routed_to_team_admin".to_string());

    scheduler
        .register(
            request_id,
            "team-z".to_string(),
            "org-admin".to_string(),
            "TeamAdmin".to_string(),
            9999, // far future
        )
        .await
        .unwrap();

    // Verify row exists before approval
    let id_str = request_id.to_string();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_escalations WHERE approval_id = ?")
        .bind(&id_str)
        .fetch_one(&check_pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "row must exist before team admin approves");

    // TeamAdmin approves before the escalation fires
    queue
        .decide(
            request_id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: Some("looks fine".to_string()),
            },
        )
        .unwrap();

    // Simulate what the gateway does: cancel the pending escalation on resolve
    let cancelled = scheduler.cancel(request_id).await.unwrap();
    assert!(cancelled, "cancel must return true when row exists");

    // Row must now be gone
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pending_escalations WHERE approval_id = ?")
        .bind(&id_str)
        .fetch_one(&check_pool)
        .await
        .unwrap();
    assert_eq!(count, 0, "row must be deleted after cancel");

    // Tick at t=0 → no escalation event (row was already removed)
    scheduler.tick().await.unwrap();
    assert!(
        escalation_rx.try_recv().is_err(),
        "no escalation event must fire when team admin approved before timeout"
    );

    // Decision future must resolve as Approved
    let decision = tokio::time::timeout(Duration::from_secs(1), decision_future)
        .await
        .expect("future must resolve within 1s")
        .expect("channel must not be closed");
    assert!(
        matches!(decision, ApprovalDecision::Approved { .. }),
        "expected Approved, got {decision:?}"
    );
}

#[tokio::test]
async fn per_policy_timeout_override_fires_at_60s_not_1800s() {
    // Team configured with 1800s default; request overrides to 60s
    let repo = in_memory_repo().await;
    repo.upsert(TeamRoutingConfig {
        team_id: "team-w".to_string(),
        approvers: vec!["alice".to_string()],
        escalation_timeout_secs: 1800,
        escalation_approvers: vec!["org-admin".to_string()],
        approval_kind: None,
    })
    .await
    .unwrap();

    let fake_clock = Arc::new(FakeClock::new(0));
    let router = ApprovalRouter::new(
        Arc::new(repo),
        Arc::new(NoopAuditSink),
        fake_clock.clone() as Arc<dyn Clock>,
    );

    let req = ApprovalRequest {
        timeout_override_secs: Some(60),
        ..make_request(Some("team-w"))
    };
    let ctx = make_ctx(Some("team-w"));
    let request_id = req.request_id;

    // Router must pick up the 60s override, not the team's 1800s
    let routing_decision = router.route(&req, &ctx).await.unwrap();
    assert_eq!(
        routing_decision.escalate_at, 60,
        "override timeout of 60s must be used, not team default of 1800s"
    );

    let queue = ApprovalQueue::new();
    let (_id, _decision_future) = queue.submit(req);
    queue.update_routing_status(request_id, "routed_to_team_admin".to_string());

    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    let (escalation_tx, mut escalation_rx) = broadcast::channel(16);
    let scheduler = DbEscalationScheduler::new(
        pool,
        fake_clock.clone() as Arc<dyn Clock>,
        Arc::clone(&queue),
        Arc::new(NoopAuditSink),
        escalation_tx,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    scheduler
        .register(
            request_id,
            "team-w".to_string(),
            "org-admin".to_string(),
            "TeamAdmin".to_string(),
            routing_decision.escalate_at, // 60
        )
        .await
        .unwrap();

    // Tick at t=0 → escalate_at=60 > now=0, must not fire
    scheduler.tick().await.unwrap();
    assert!(escalation_rx.try_recv().is_err(), "must not fire before t=60");

    // Tick at t=61 → fires at 60s boundary, not at 1800s
    fake_clock.set(61);
    scheduler.tick().await.unwrap();
    let event = escalation_rx
        .try_recv()
        .expect("escalation must fire at the 60s override, not at 1800s");
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.escalation_approvers, vec!["org-admin"]);
}
