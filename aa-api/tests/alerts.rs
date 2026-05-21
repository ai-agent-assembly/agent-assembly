//! Integration tests for the alerts endpoint.

mod common;

use std::collections::BTreeMap;

use aa_api::alerts::detail::{RoutingLogEntry, RuleSnapshot};
use aa_api::alerts::{DedupOutcome, RuleAlertSeed};
use aa_core::AgentId;
use aa_gateway::budget::types::BudgetAlert;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn list_alerts_returns_200_empty() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
    assert_eq!(json["page"], 1);
}

#[tokio::test]
async fn list_alerts_respects_pagination_params() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts?page=3&per_page=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["page"], 3);
    assert_eq!(json["per_page"], 5);
}

#[tokio::test]
async fn list_alerts_returns_alerts_after_recording() {
    let state = common::test_state();
    let alert_store = state.alert_store.clone();

    // Record an alert directly into the store.
    let alert = BudgetAlert {
        agent_id: AgentId::from_bytes([0xAB; 16]),
        team_id: None,
        threshold_pct: 80,
        spent_usd: 8.0,
        limit_usd: 10.0,
    };
    alert_store.record(&alert);

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["severity"], "warning");
    assert_eq!(items[0]["category"], "budget");
    assert!(items[0]["message"].as_str().unwrap().contains("80%"));
    assert!(items[0]["agent_id"].is_string());
    assert!(items[0]["timestamp"].is_string());
    assert!(items[0]["id"].is_string());
}

#[tokio::test]
async fn list_alerts_via_broadcast_capture() {
    let state = common::test_state();
    let budget_tx = state.events.budget_sender();
    let budget_rx = state.events.subscribe_budget();
    let alert_store = state.alert_store.clone();

    // Spawn the capture task.
    let _handle = aa_api::alerts::capture::spawn_alert_capture(budget_rx, alert_store);

    // Send an alert via broadcast.
    let alert = BudgetAlert {
        agent_id: AgentId::from_bytes([0xCD; 16]),
        team_id: None,
        threshold_pct: 95,
        spent_usd: 9.5,
        limit_usd: 10.0,
    };
    budget_tx.send(alert).unwrap();

    // Give the capture task a moment to process.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items[0]["severity"], "critical");
}

#[tokio::test]
async fn list_alerts_pagination_with_multiple_alerts() {
    let state = common::test_state();
    let alert_store = state.alert_store.clone();

    // Record 5 alerts.
    for i in 0..5u8 {
        let alert = BudgetAlert {
            agent_id: AgentId::from_bytes([i + 1; 16]),
            team_id: None,
            threshold_pct: 80 + i,
            spent_usd: 8.0 + f64::from(i),
            limit_usd: 15.0,
        };
        alert_store.record(&alert);
    }

    let app = aa_api::server::build_app(state);

    // Request page 1 with 2 items per page.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts?page=1&per_page=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 5);
    assert_eq!(json["page"], 1);
    assert_eq!(json["per_page"], 2);
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // Newest first — assert ULID format and lexicographic ordering.
    let id0 = items[0]["id"].as_str().unwrap();
    let id1 = items[1]["id"].as_str().unwrap();
    assert_eq!(id0.len(), 26);
    assert_eq!(id1.len(), 26);
    assert!(id0 > id1, "newest-first: {id0} must sort after {id1}");

    // Request page 3 with 2 items per page → should get 1 item (oldest).
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts?page=3&per_page=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let oldest = items[0]["id"].as_str().unwrap();
    assert_eq!(oldest.len(), 26);
    assert!(oldest < id1, "page-3 entry must be older than page-1 entries");
}

// ============================================================================
// GET /api/v1/alerts/:id  (AAASM-1474)
// ============================================================================

#[tokio::test]
async fn get_alert_returns_200_with_full_detail_for_known_id() {
    let state = common::test_state();
    let alert_store = state.alert_store.clone();

    let id = alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes([0x11; 16]),
        team_id: None,
        threshold_pct: 95,
        spent_usd: 9.5,
        limit_usd: 10.0,
    });

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/alerts/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], id.to_string());
    assert_eq!(json["severity"], "critical");
    assert_eq!(json["status"], "unresolved");
    assert!(json["updated_at"].is_null(), "updated_at must be null pre-resolve");
}

#[tokio::test]
async fn get_alert_returns_404_for_unknown_id() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts/00000000000000000000000000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_alert_returns_404_for_unrecognized_id() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts/not-a-ulid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// POST /api/v1/alerts/:id/resolve  (AAASM-1474)
// ============================================================================

#[tokio::test]
async fn resolve_alert_flips_status_and_sets_updated_at() {
    let state = common::test_state();
    let alert_store = state.alert_store.clone();
    let id = alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes([0x22; 16]),
        team_id: None,
        threshold_pct: 90,
        spent_usd: 9.0,
        limit_usd: 10.0,
    });

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/alerts/{id}/resolve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"ack"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "resolved");
    assert!(json["updated_at"].is_string(), "updated_at must be set post-resolve");
}

#[tokio::test]
async fn resolve_alert_is_idempotent_on_second_call() {
    let state = common::test_state();
    let alert_store = state.alert_store.clone();
    let id = alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes([0x33; 16]),
        team_id: None,
        threshold_pct: 85,
        spent_usd: 8.5,
        limit_usd: 10.0,
    });

    let app = aa_api::server::build_app(state);

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/alerts/{id}/resolve"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let first_body = axum::body::to_bytes(first.into_body(), usize::MAX).await.unwrap();
    let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
    let first_updated_at = first_json["updated_at"].clone();

    let second = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/alerts/{id}/resolve"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_body = axum::body::to_bytes(second.into_body(), usize::MAX).await.unwrap();
    let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();

    assert_eq!(second_json["status"], "resolved");
    assert_eq!(
        second_json["updated_at"], first_updated_at,
        "second resolve must not bump updated_at",
    );
}

// ============================================================================
// AAASM-1385 — rich alert detail + dedup integration tests (AAASM-1629)
// ============================================================================

fn test_rule_seed() -> RuleAlertSeed {
    RuleAlertSeed {
        agent_id: Some(AgentId::from_bytes([0x77; 16])),
        team_id: Some("team-platform".to_string()),
        rule_id: "rule-budget-90".to_string(),
        rule_name: "Budget threshold > 90%".to_string(),
        rule_snapshot: RuleSnapshot {
            metric: "budget_spent_pct".to_string(),
            operator: ">".to_string(),
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: "CRITICAL".to_string(),
            dedup_window_seconds: 600,
            suppression_labels: BTreeMap::new(),
        },
        destination_ids: vec!["slack-ops".to_string()],
        event_payload: serde_json::json!({ "metric_value": 92.3 }),
        routing_log: vec![RoutingLogEntry {
            destination_id: "slack-ops".to_string(),
            delivered_at: "2026-05-20T09:00:01Z".to_string(),
            status: "ok".to_string(),
        }],
    }
}

async fn get_alert_json(app: axum::Router, id: &str) -> serde_json::Value {
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/alerts/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn get_alert_returns_rich_detail_for_rule_alert() {
    let state = common::test_state();
    let id = state.alert_store.record_rule_alert(&test_rule_seed());

    let app = aa_api::server::build_app(state);
    let json = get_alert_json(app, &id).await;

    assert_eq!(json["id"], id.to_string());
    assert_eq!(json["rule_id"], "rule-budget-90");
    assert_eq!(json["rule_name"], "Budget threshold > 90%");
    assert_eq!(json["rule_snapshot"]["metric"], "budget_spent_pct");
    assert_eq!(json["rule_snapshot"]["dedup_window_seconds"], 600);
    assert_eq!(json["category"], "rule");
    assert_eq!(json["destination_ids"][0], "slack-ops");
    assert_eq!(json["event_payload"]["metric_value"], 92.3);
    assert_eq!(json["routing_log"][0]["destination_id"], "slack-ops");
    assert_eq!(json["dedup_occurrence_count"], 1);
}

#[tokio::test]
async fn get_alert_returns_null_rule_context_for_budget_alert() {
    let state = common::test_state();
    let id = state.alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes([0x88; 16]),
        team_id: None,
        threshold_pct: 95,
        spent_usd: 9.5,
        limit_usd: 10.0,
    });

    let app = aa_api::server::build_app(state);
    let json = get_alert_json(app, &id).await;

    assert!(json["rule_id"].is_null(), "rule_id must be null for budget alerts");
    assert!(
        json["rule_snapshot"].is_null(),
        "rule_snapshot must be null for budget alerts"
    );
    assert_eq!(json["destination_ids"].as_array().unwrap().len(), 0);
    assert_eq!(json["routing_log"].as_array().unwrap().len(), 0);
    assert!(json["event_payload"].is_null());
    assert_eq!(json["dedup_occurrence_count"], 1);
    assert!(json["dedup_window_expires_at"].is_null());
    assert_eq!(json["category"], "budget");
}

#[tokio::test]
async fn dedup_refire_within_window_increments_count_and_does_not_reroute() {
    let state = common::test_state();
    let seed = test_rule_seed();

    let now = chrono::DateTime::parse_from_rfc3339("2026-05-20T09:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let (id, first_outcome) = state.alert_store.dedup_or_record_rule_alert(&seed, now);
    assert_eq!(first_outcome, DedupOutcome::Created);

    // Re-fire 5 minutes later — still inside the 600-second window.
    let later = now + chrono::Duration::seconds(300);
    let (id2, second_outcome) = state.alert_store.dedup_or_record_rule_alert(&seed, later);
    assert_eq!(id2, id, "dedup must absorb into the existing alert");
    assert_eq!(
        second_outcome,
        DedupOutcome::Deduped {
            existing_id: id.clone()
        }
    );

    let app = aa_api::server::build_app(state);
    let json = get_alert_json(app, &id).await;

    assert_eq!(json["dedup_occurrence_count"], 2);
    assert_eq!(
        json["routing_log"].as_array().unwrap().len(),
        seed.routing_log.len(),
        "dedup must NOT append to routing_log",
    );
}

#[tokio::test]
async fn dedup_refire_after_window_creates_new_alert_with_fresh_routing() {
    let state = common::test_state();
    let seed = test_rule_seed();

    let now = chrono::DateTime::parse_from_rfc3339("2026-05-20T09:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let (first_id, _) = state.alert_store.dedup_or_record_rule_alert(&seed, now);

    // Re-fire 700 seconds later — past the 600-second window.
    let later = now + chrono::Duration::seconds(700);
    let (second_id, outcome) = state.alert_store.dedup_or_record_rule_alert(&seed, later);
    assert_eq!(outcome, DedupOutcome::Created);
    assert_ne!(second_id, first_id, "post-expiry re-fire must allocate a new id");

    let app = aa_api::server::build_app(state);
    let json = get_alert_json(app, &second_id).await;

    assert_eq!(json["dedup_occurrence_count"], 1);
    assert!(
        json["dedup_window_expires_at"].is_string(),
        "fresh window must populate dedup_window_expires_at",
    );
    assert!(
        !json["routing_log"].as_array().unwrap().is_empty(),
        "fresh fire must carry routing_log seeded by the rule engine",
    );
}

#[tokio::test]
async fn resolve_alert_returns_404_for_unknown_id() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/alerts/00000000000000000000000000/resolve")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
