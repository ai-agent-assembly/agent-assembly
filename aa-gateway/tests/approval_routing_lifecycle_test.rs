//! Integration test for the full team-approval-routing lifecycle.
//!
//! Covers AC6: route to team → no action → timer fires → escalate to OrgAdmin → approve;
//! asserts state transitions and that the correct routing and escalation events are produced.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use uuid::Uuid;

use aa_core::PolicyResult;
use aa_gateway::approval::escalation::EscalationScheduler;
use aa_gateway::approval::router::{ApprovalRouter, RoutingOutcome};
use aa_gateway::approval::routing_config::{RoutingConfigStore, TeamRoutingConfig};
use aa_runtime::approval::{ApprovalDecision, ApprovalQueue, ApprovalRequest};

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
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[test]
fn router_resolves_team_and_approvers() {
    let store_path = temp_path("router");
    let mut store = RoutingConfigStore::load(&store_path).unwrap();
    store
        .upsert(TeamRoutingConfig {
            team_id: "team-alpha".to_string(),
            approvers: vec!["alice".to_string(), "bob".to_string()],
            escalation_timeout_secs: 1800,
            escalation_approvers: vec!["org-admin".to_string()],
        })
        .unwrap();

    let router = ApprovalRouter::new(store);
    let req = make_request(Some("team-alpha"));

    match router.route(&req) {
        RoutingOutcome::Routed {
            team_id,
            approvers,
            escalation_timeout_secs,
        } => {
            assert_eq!(team_id, "team-alpha");
            assert_eq!(approvers, vec!["alice", "bob"]);
            assert_eq!(escalation_timeout_secs, 1800);
        }
        other => panic!("expected Routed, got {other:?}"),
    }
}

#[test]
fn router_no_team_id_returns_no_team_id() {
    let store_path = temp_path("no_team");
    let store = RoutingConfigStore::load(&store_path).unwrap();
    let router = ApprovalRouter::new(store);
    let req = make_request(None);
    assert_eq!(router.route(&req), RoutingOutcome::NoTeamId);
}

#[test]
fn router_unknown_team_returns_no_team_config() {
    let store_path = temp_path("unknown");
    let store = RoutingConfigStore::load(&store_path).unwrap();
    let router = ApprovalRouter::new(store);
    let req = make_request(Some("team-not-configured"));
    assert_eq!(router.route(&req), RoutingOutcome::NoTeamConfig);
}

#[tokio::test]
async fn escalation_fires_immediately_when_timeout_is_zero() {
    let path = temp_path("escalation_zero");
    let (tx, mut rx) = broadcast::channel(16);
    let scheduler = Arc::new(
        EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap(),
    );

    let request_id = Uuid::new_v4();
    scheduler
        .register(
            request_id,
            "team-beta".to_string(),
            vec!["org-admin".to_string()],
            0, // timeout_secs = 0 → immediately overdue
        )
        .unwrap();

    // Tick manually — no need to wait for the background loop.
    scheduler.tick();

    let event = rx.try_recv().expect("escalation event should fire immediately");
    assert_eq!(event.request_id, request_id);
    assert_eq!(event.team_id, "team-beta");
    assert_eq!(event.escalation_approvers, vec!["org-admin"]);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn escalation_does_not_fire_when_not_yet_overdue() {
    let path = temp_path("not_overdue");
    let (tx, mut rx) = broadcast::channel(16);
    let scheduler = Arc::new(
        EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap(),
    );

    let request_id = Uuid::new_v4();
    // 1 hour in the future → not yet overdue
    scheduler
        .register(request_id, "team-gamma".to_string(), vec![], 3600)
        .unwrap();

    scheduler.tick();

    assert!(rx.try_recv().is_err(), "escalation must not fire before the timeout");

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn full_lifecycle_route_escalate_approve() {
    let store_path = temp_path("lifecycle_store");
    let escalation_path = temp_path("lifecycle_escalation");

    // 1. Routing config: team-x with immediate escalation
    let mut store = RoutingConfigStore::load(&store_path).unwrap();
    store
        .upsert(TeamRoutingConfig {
            team_id: "team-x".to_string(),
            approvers: vec!["alice".to_string()],
            escalation_timeout_secs: 0, // fires immediately
            escalation_approvers: vec!["org-admin".to_string()],
        })
        .unwrap();

    // 2. Route the request
    let router = ApprovalRouter::new(store);
    let req = make_request(Some("team-x"));
    let request_id = req.request_id;

    let routing_outcome = router.route(&req);
    let escalation_timeout = match &routing_outcome {
        RoutingOutcome::Routed {
            team_id,
            escalation_timeout_secs,
            ..
        } => {
            assert_eq!(team_id, "team-x");
            *escalation_timeout_secs
        }
        other => panic!("expected Routed, got {other:?}"),
    };

    // 3. Submit to approval queue
    let queue = Arc::new(ApprovalQueue::new());
    let (_id, decision_future) = queue.submit(req);

    // 4. Register with escalation scheduler
    let (tx, mut escalation_rx) = broadcast::channel(16);
    let scheduler = Arc::new(
        EscalationScheduler::new(&escalation_path, tx, Duration::from_millis(50)).unwrap(),
    );
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

    let _ = std::fs::remove_file(&store_path);
    let _ = std::fs::remove_file(&escalation_path);
}

#[tokio::test]
async fn escalation_cancel_on_decision_removes_pending_entry() {
    let path = temp_path("cancel_on_decide");
    let (tx, _rx) = broadcast::channel(16);
    let scheduler = Arc::new(
        EscalationScheduler::new(&path, tx, Duration::from_millis(50)).unwrap(),
    );

    let request_id = Uuid::new_v4();
    // Register with a long timeout so it won't fire on its own.
    scheduler
        .register(request_id, "team-y".to_string(), vec![], 3600)
        .unwrap();

    // Simulate decision: cancel the escalation
    let cancelled = scheduler.cancel(request_id).unwrap();
    assert!(cancelled, "cancel must return true for a registered entry");

    // Second cancel returns false (already removed)
    let second = scheduler.cancel(request_id).unwrap();
    assert!(!second);

    let _ = std::fs::remove_file(&path);
}
