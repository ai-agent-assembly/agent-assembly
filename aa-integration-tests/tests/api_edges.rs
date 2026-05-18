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

/// Seed one directed edge via HTTP and return its assigned id.
async fn seed_edge(base_url: &str, src: &str, tgt: &str, edge_type: &str) -> i64 {
    let resp = reqwest::Client::new()
        .post(format!("{base_url}/api/v1/topology/edges"))
        .json(&serde_json::json!({
            "source_agent_id": src,
            "target_agent_id": tgt,
            "edge_type": edge_type,
        }))
        .send()
        .await
        .expect("POST /topology/edges should not fail");
    assert_eq!(resp.status(), StatusCode::CREATED, "seed_edge expects 201");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["id"].as_i64().expect("response must have numeric id")
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

// ---------------------------------------------------------------------------
// GET /api/v1/topology/edges
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn edge_list_topology_empty_returns_zero_count() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");

    let resp = reqwest::get(format!("{}/api/v1/topology/edges", env.base_url()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 0);
    assert!(body["edges"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_list_topology_returns_all_seeded_edges() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let base = env.base_url();

    seed_edge(&base, &agent_hex(0x0a), &agent_hex(0x0b), "calls").await;
    seed_edge(&base, &agent_hex(0x0c), &agent_hex(0x0d), "reads").await;

    let resp = reqwest::get(format!("{base}/api/v1/topology/edges")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 2, "expected 2 seeded edges");
    assert_eq!(body["edges"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_list_topology_limit_caps_results() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let base = env.base_url();

    for i in 0x10_u8..0x13 {
        seed_edge(&base, &agent_hex(i), &agent_hex(0xff), "delegates_to").await;
    }

    let resp = reqwest::get(format!("{base}/api/v1/topology/edges?limit=2"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 2, "limit=2 should cap at 2 edges");
    assert_eq!(body["edges"].as_array().unwrap().len(), 2);
}
