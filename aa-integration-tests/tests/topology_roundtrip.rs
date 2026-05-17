//! AAASM-1079 / ST-3 — three assertion tests for the topology pipeline.
//!
//! `agent_record_has_correct_parent_and_depth` — asserts the registry-level
//! lineage shape on the child record. (Ticket AC text says "queries Postgres
//! directly"; the actual backing store is an in-memory `DashMap` exposed
//! through `Arc<AgentRegistry>` — same data, different read path. See ST-1
//! divergence notes.)
//!
//! `rest_tree_endpoint_returns_two_node_shape` — hits
//! `GET /api/v1/topology/tree/{root_id}` and asserts the JSON shape.
//!
//! `cli_topology_tree_renders_both_agents` — runs `aasm topology tree
//! <root> --api-url http://127.0.0.1:PORT` via `cargo run -p aa-cli` and
//! asserts both agent IDs appear in stdout.
//!
//! ## Divergence from the ticket AC: no shared `OnceCell` across tests
//!
//! Sharing a single `TopologyTestEnv` across multiple `#[tokio::test]`
//! cases via `OnceCell` is non-trivial: each `#[tokio::test]` creates an
//! independent Tokio runtime, so the axum server task spawned during the
//! first test's runtime is killed when that runtime is dropped, breaking
//! subsequent tests. A correct shared-fixture impl needs a dedicated
//! host thread that owns a long-lived runtime + the server task. That's
//! ~30 LOC of plumbing for a per-test cost of ~50 ms; for ST-3 we accept
//! the per-test boot and revisit if any later test gets expensive.

mod common;

use std::process::Command;

use common::scenario::{hex_id, register_parent_child};
use common::TopologyTestEnv;

#[tokio::test(flavor = "multi_thread")]
async fn agent_record_has_correct_parent_and_depth() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let (parent_id, child_id) = register_parent_child(&env);

    let child = env
        .agent_registry
        .get(&child_id)
        .expect("child record should be present after scenario setup");

    assert_eq!(child.depth, 1, "child depth should be 1 (root is 0)");
    assert_eq!(
        child.parent_key,
        Some(parent_id),
        "child parent_key should reference the root agent",
    );
    assert_eq!(
        child.parent_agent_id.as_deref(),
        Some(hex_id(&parent_id).as_str()),
        "child parent_agent_id (string form) should match root's id",
    );
    assert_eq!(
        child.root_agent_id,
        Some(parent_id),
        "child root_agent_id should resolve to the root",
    );
    assert_eq!(
        child.team_id.as_deref(),
        Some("topology-it"),
        "child team_id should be the harness team",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_tree_endpoint_returns_two_node_shape() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let (parent_id, child_id) = register_parent_child(&env);
    let root_id = hex_id(&parent_id);
    let child_id_str = hex_id(&child_id);

    let url = format!("{}/api/v1/topology/tree/{root_id}", env.base_url());
    let resp = reqwest::get(&url).await.expect("REST request should succeed");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "tree endpoint should return 200"
    );

    let tree: serde_json::Value = resp.json().await.expect("tree response should parse as JSON");

    assert_eq!(tree["id"], root_id, "root node id should equal the root agent id");
    let children = tree["children"].as_array().expect("children should be an array");
    assert_eq!(children.len(), 1, "root should have exactly one child");

    let child = &children[0];
    assert_eq!(
        child["id"], child_id_str,
        "child node id should equal the child agent id"
    );
    let grandchildren = child["children"].as_array().expect("child.children should be an array");
    assert!(grandchildren.is_empty(), "child should have no further children");
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_topology_tree_renders_both_agents() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let (parent_id, child_id) = register_parent_child(&env);
    let root_id = hex_id(&parent_id);
    let child_id_str = hex_id(&child_id);
    let api_url = env.base_url();

    // `assert_cmd::Command::cargo_bin` requires `CARGO_BIN_EXE_<name>` which
    // Cargo only sets for the bin's own crate. `aasm` lives in `aa-cli`, a
    // sibling crate — so we invoke via `cargo run` from this crate's manifest
    // dir. The binary is cached after the first build.
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "-p",
            "aa-cli",
            "--bin",
            "aasm",
            "--",
            "--api-url",
            &api_url,
            "--output",
            "json",
            "topology",
            "tree",
            &root_id,
        ])
        .output()
        .expect("aasm topology tree should execute via cargo run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "aasm should exit 0; stdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stdout.contains(&root_id),
        "stdout should contain root agent id {root_id}\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains(&child_id_str),
        "stdout should contain child agent id {child_id_str}\nstdout:\n{stdout}",
    );
}
