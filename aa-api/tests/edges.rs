//! Integration tests for the mesh topology edge endpoints.
//!
//! Covers:
//!   POST /topology/edges        — record a new edge
//!   GET  /agents/{id}/edges     — list edges (outgoing/incoming, filter, limit)
//!   GET  /agents/{id}/graph     — BFS subgraph

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use aa_api::server::build_app;
use aa_core::identity::AgentId;
use aa_core::topology::NewEdge;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(16)
}

fn agent_id(byte: u8) -> AgentId {
    AgentId::from_bytes([byte; 16])
}

async fn post_edge(app: axum::Router, body: Value) -> (StatusCode, Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/topology/edges")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

// ---------------------------------------------------------------------------
// POST /topology/edges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn report_edge_returns_201_with_id() {
    let app = common::test_app();
    let (status, body) = post_edge(
        app,
        json!({
            "source_agent_id": hex(0x01),
            "target_agent_id": hex(0x02),
            "edge_type": "messages"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["id"].is_number(), "expected numeric id in response");
}

#[tokio::test]
async fn report_edge_invalid_source_returns_400() {
    let app = common::test_app();
    let (status, _) = post_edge(
        app,
        json!({
            "source_agent_id": "not-hex",
            "target_agent_id": hex(0x02),
            "edge_type": "messages"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn report_edge_invalid_edge_type_returns_400() {
    let app = common::test_app();
    let (status, _) = post_edge(
        app,
        json!({
            "source_agent_id": hex(0x01),
            "target_agent_id": hex(0x02),
            "edge_type": "unknown_type"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn report_edge_with_metadata_json() {
    let app = common::test_app();
    let (status, body) = post_edge(
        app,
        json!({
            "source_agent_id": hex(0x01),
            "target_agent_id": hex(0x02),
            "edge_type": "delegates_to",
            "metadata_json": r#"{"reason":"subtask"}"#
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(body["id"].is_number());
}

// ---------------------------------------------------------------------------
// GET /agents/{id}/edges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_agent_edges_empty_returns_200_with_empty_list() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/edges", hex(0xAA)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["count"], 0);
    assert!(json["edges"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_agent_edges_outgoing_returns_correct_edges() {
    let state = common::test_state();
    // Insert two outgoing edges from 0x01
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x02),
            edge_type: aa_core::topology::EdgeType::Messages,
            metadata: None,
        })
        .await
        .unwrap();
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x03),
            edge_type: aa_core::topology::EdgeType::DelegatesTo,
            metadata: None,
        })
        .await
        .unwrap();
    // Insert one edge FROM another agent (should not appear in outgoing for 0x01)
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x02),
            target: agent_id(0x01),
            edge_type: aa_core::topology::EdgeType::Messages,
            metadata: None,
        })
        .await
        .unwrap();

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/edges?direction=outgoing", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["count"], 2);
    let edges = json["edges"].as_array().unwrap();
    let types: Vec<&str> = edges.iter().map(|e| e["edge_type"].as_str().unwrap()).collect();
    assert!(types.contains(&"messages"));
    assert!(types.contains(&"delegates_to"));
}

#[tokio::test]
async fn list_agent_edges_incoming_direction() {
    let state = common::test_state();
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x02),
            target: agent_id(0x01),
            edge_type: aa_core::topology::EdgeType::Messages,
            metadata: None,
        })
        .await
        .unwrap();

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/edges?direction=incoming", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["count"], 1);
    assert_eq!(json["edges"][0]["source_agent_id"], hex(0x02));
}

#[tokio::test]
async fn list_agent_edges_type_filter() {
    let state = common::test_state();
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x02),
            edge_type: aa_core::topology::EdgeType::Messages,
            metadata: None,
        })
        .await
        .unwrap();
    state
        .edge_repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x03),
            edge_type: aa_core::topology::EdgeType::DelegatesTo,
            metadata: None,
        })
        .await
        .unwrap();

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/edges?type=messages", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["count"], 1);
    assert_eq!(json["edges"][0]["edge_type"], "messages");
}

// ---------------------------------------------------------------------------
// GET /agents/{id}/graph — 4-agent subgraph
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_agent_graph_four_agent_chain() {
    // Build: A -> B -> C -> D (linear chain, depth=3 from A covers all)
    let state = common::test_state();
    for (src, tgt) in [(0x01u8, 0x02u8), (0x02, 0x03), (0x03, 0x04)] {
        state
            .edge_repo
            .insert(NewEdge {
                source: agent_id(src),
                target: agent_id(tgt),
                edge_type: aa_core::topology::EdgeType::Messages,
                metadata: None,
            })
            .await
            .unwrap();
    }

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/graph?depth=3", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    let nodes = json["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 4, "all 4 agents should be in the subgraph");

    let edges = json["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 3, "3 edges in the chain");

    // All edges should have is_cross_team = false (no registry entries)
    for edge in edges {
        assert_eq!(edge["is_cross_team"], false);
    }
}

#[tokio::test]
async fn get_agent_graph_depth_limits_reachability() {
    // A -> B -> C -> D; with depth=1 only B is reachable from A
    let state = common::test_state();
    for (src, tgt) in [(0x01u8, 0x02u8), (0x02, 0x03), (0x03, 0x04)] {
        state
            .edge_repo
            .insert(NewEdge {
                source: agent_id(src),
                target: agent_id(tgt),
                edge_type: aa_core::topology::EdgeType::Messages,
                metadata: None,
            })
            .await
            .unwrap();
    }

    let app = build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/graph?depth=1", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    // depth=1 means BFS stops at d >= 1, so only A and B are visited
    let nodes = json["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
}

#[tokio::test]
async fn get_agent_graph_root_only_when_no_edges() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/graph", hex(0x01)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();

    let nodes = json["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1, "only the root node when no edges");
    assert!(json["edges"].as_array().unwrap().is_empty());
}
