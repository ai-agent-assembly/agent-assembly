//! Integration tests for the alerts endpoint.

mod common;

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
