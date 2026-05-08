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

/// Create a `RoutingConfigStore` pre-populated with a single team config.
fn make_routing_store(suffix: &str, cfg: TeamRoutingConfig) -> RoutingConfigStore {
    let path = temp_path(suffix);
    let mut store = RoutingConfigStore::load(&path).unwrap();
    store.upsert(cfg).unwrap();
    store
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[test]
fn router_resolves_team_and_approvers() {
    let store = make_routing_store(
        "router",
        TeamRoutingConfig {
            team_id: "team-alpha".to_string(),
            approvers: vec!["alice".to_string(), "bob".to_string()],
            escalation_timeout_secs: 1800,
            escalation_approvers: vec!["org-admin".to_string()],
        },
    );
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
async fn full_lifecycle_route_escalate_approve() {
    // 1. Routing config: team-x with immediate escalation
    let store = make_routing_store(
        "lifecycle_store",
        TeamRoutingConfig {
            team_id: "team-x".to_string(),
            approvers: vec!["alice".to_string()],
            escalation_timeout_secs: 0, // fires immediately
            escalation_approvers: vec!["org-admin".to_string()],
        },
    );

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

    let _ = std::fs::remove_file(&escalation_path);
}
