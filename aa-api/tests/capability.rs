//! Integration tests for the dashboard Capability Matrix endpoint (AAASM-1366).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn get_matrix_returns_200_with_dashboard_shape() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/matrix")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Top-level shape mirrors dashboard's `CapabilityMatrix` interface.
    assert!(json["resources"].is_array(), "resources must be an array");
    assert!(json["agents"].is_array(), "agents must be an array");
    assert!(json["policies"].is_array(), "policies must be an array");
    assert!(
        json["sampleCalls"].is_array(),
        "sampleCalls must be camelCase, not sample_calls"
    );
    assert!(
        json.get("sample_calls").is_none(),
        "snake_case sample_calls must not appear"
    );

    // Seed contract: 8 resources covering every group.
    assert_eq!(json["resources"].as_array().unwrap().len(), 8);

    // Seed contract: every agent has a cell for every resource, and the
    // cell carries decisions for all four verbs.
    let resource_ids: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(!resource_ids.is_empty());

    let agents = json["agents"].as_array().unwrap();
    assert!(!agents.is_empty(), "seed must include at least one agent");
    for agent in agents {
        // CapabilityAgent uses camelCase `lastSeen`.
        assert!(agent["lastSeen"].is_string(), "agent {} missing lastSeen", agent["id"]);
        for rid in &resource_ids {
            let cell = &agent["caps"][rid];
            assert!(
                cell.is_object(),
                "agent {} missing cell for resource {rid}",
                agent["id"]
            );
            for verb in ["read", "write", "delete", "exec"] {
                assert!(
                    cell[verb].is_string(),
                    "agent {} resource {rid} missing decision for {verb}",
                    agent["id"]
                );
            }
        }
    }
}
