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

// ---------------------------------------------------------------------------
// GET /api/v1/agents/{id}/edges
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn edge_list_agent_empty_returns_zero_count() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let id = agent_hex(0x20);

    let resp = reqwest::get(format!("{}/api/v1/agents/{id}/edges", env.base_url()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 0);
    assert!(body["edges"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_list_agent_outgoing_direction_is_default() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let base = env.base_url();
    let src = agent_hex(0x21);
    let tgt = agent_hex(0x22);

    seed_edge(&base, &src, &tgt, "writes").await;

    // src has 1 outgoing edge
    let resp = reqwest::get(format!("{base}/api/v1/agents/{src}/edges")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 1);
    assert_eq!(body["edges"][0]["edge_type"], "writes");

    // tgt has 0 outgoing (direction defaults to outgoing)
    let resp2 = reqwest::get(format!("{base}/api/v1/agents/{tgt}/edges")).await.unwrap();
    let body2: serde_json::Value = resp2.json().await.unwrap();
    assert_eq!(
        body2["count"], 0,
        "default direction=outgoing: tgt has no outgoing edges"
    );
}

// ---------------------------------------------------------------------------
// GET /api/v1/agents/{id}/graph
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn edge_graph_root_only_when_no_edges() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let id = agent_hex(0x30);

    let resp = reqwest::get(format!("{}/api/v1/agents/{id}/graph", env.base_url()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["root_agent_id"], id);
    assert_eq!(body["nodes"].as_array().unwrap().len(), 1, "only root node");
    assert!(body["edges"].as_array().unwrap().is_empty(), "no edges");
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_graph_bfs_two_hop_chain() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let base = env.base_url();
    let a = agent_hex(0x31);
    let b = agent_hex(0x32);
    let c = agent_hex(0x33);

    // a → b → c  (2-hop chain; depth defaults to 2)
    seed_edge(&base, &a, &b, "calls").await;
    seed_edge(&base, &b, &c, "calls").await;

    let resp = reqwest::get(format!("{base}/api/v1/agents/{a}/graph?depth=2"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["root_agent_id"], a);
    assert_eq!(
        body["nodes"].as_array().unwrap().len(),
        3,
        "a, b, c all reachable within depth 2"
    );
    assert_eq!(body["edges"].as_array().unwrap().len(), 2, "two edges: a→b and b→c");
}

#[tokio::test(flavor = "multi_thread")]
async fn edge_graph_depth_cap_limits_reachability() {
    let env = common::TopologyTestEnv::start().await.expect("harness start");
    let base = env.base_url();
    let a = agent_hex(0x41);
    let b = agent_hex(0x42);
    let c = agent_hex(0x43);

    // a → b → c, depth=1 should reach b but not c
    seed_edge(&base, &a, &b, "delegates_to").await;
    seed_edge(&base, &b, &c, "delegates_to").await;

    let resp = reqwest::get(format!("{base}/api/v1/agents/{a}/graph?depth=1"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2, "depth=1: only a and b, not c");

    let node_ids: Vec<&str> = nodes.iter().map(|n| n["id"].as_str().unwrap()).collect();
    assert!(node_ids.contains(&a.as_str()), "root a must be in nodes");
    assert!(node_ids.contains(&b.as_str()), "b must be in nodes at depth 1");
}
