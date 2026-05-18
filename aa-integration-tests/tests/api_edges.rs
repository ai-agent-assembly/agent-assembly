//! AAASM-1491 / F122 ST-J — live-gateway integration tests for topology edge endpoints.
//!
//! Route surface (4 handlers in `aa-api/src/routes/edges.rs`):
//!   POST /api/v1/topology/edges           — record a new directed edge
//!   GET  /api/v1/topology/edges           — list all edges, optional team filter
//!   GET  /api/v1/agents/{id}/edges        — per-agent edge list (direction/type/limit/before)
//!   GET  /api/v1/agents/{id}/graph        — BFS subgraph up to depth hops

mod common;

use reqwest::StatusCode;

fn agent_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(16)
}

// ---------------------------------------------------------------------------
// POST /api/v1/topology/edges
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn edge_report_returns_201_with_id() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/topology/edges", env.base_url()))
        .json(&serde_json::json!({
            "source_agent_id": agent_hex(0x01),
            "target_agent_id": agent_hex(0x02),
            "edge_type": "messages",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["id"].is_i64() || body["id"].is_u64(),
        "response must have numeric 'id'"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_report_invalid_agent_id_returns_400() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/topology/edges", env.base_url()))
        .json(&serde_json::json!({
            "source_agent_id": "not-a-hex-id",
            "target_agent_id": agent_hex(0x02),
            "edge_type": "calls",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_report_invalid_edge_type_returns_400() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/topology/edges", env.base_url()))
        .json(&serde_json::json!({
            "source_agent_id": agent_hex(0x01),
            "target_agent_id": agent_hex(0x02),
            "edge_type": "unknown_type",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
