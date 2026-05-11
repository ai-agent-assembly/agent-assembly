//! E2E tests for `aasm topology` subcommands via the compiled binary.
//!
//! Each test starts a wiremock HTTP server, invokes the real `aasm` binary
//! via assert_cmd, and asserts exit code 0 plus non-empty stdout.

use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_overview_json() -> serde_json::Value {
    serde_json::json!({
        "team_count": 2,
        "root_agent_count": 3,
        "total_agent_count": 12,
        "teams": [
            {"team_id": "team-alpha", "agent_count": 7, "root_agent_count": 1},
            {"team_id": "team-beta",  "agent_count": 5, "root_agent_count": 2}
        ],
        "standalone_root_agents": []
    })
}

#[tokio::test]
async fn e2e_topology_overview_table() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/topology/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_overview_json()))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "topology", "overview"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "stdout should not be empty");
}

#[tokio::test]
async fn e2e_topology_overview_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/topology/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_overview_json()))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "--output", "json", "topology", "overview"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "JSON stdout should not be empty");
}

#[tokio::test]
async fn e2e_topology_tree() {
    let server = MockServer::start().await;
    let root_id = "0102030405060708090a0b0c0d0e0f10";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/tree/{root_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": root_id,
            "name": "root-agent",
            "depth": 0,
            "status": "active",
            "team_id": "team-alpha",
            "delegation_reason": null,
            "spawned_by_tool": null,
            "children": []
        })))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "topology", "tree", root_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "stdout should not be empty");
}

#[tokio::test]
async fn e2e_topology_team() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/topology/team/team-alpha"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "team_id": "team-alpha",
            "agent_count": 2,
            "members": [
                {"id": "aabb", "name": "agent-1", "depth": 0, "status": "active", "team_id": "team-alpha"},
                {"id": "ccdd", "name": "agent-2", "depth": 1, "status": "active", "team_id": "team-alpha"}
            ]
        })))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "topology", "team", "team-alpha"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "stdout should not be empty");
}

#[tokio::test]
async fn e2e_topology_lineage() {
    let server = MockServer::start().await;
    let agent_id = "aabbccdd00112233aabbccdd00112233";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/lineage/{agent_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": agent_id,
            "ancestor_count": 2,
            "ancestors": [
                {"id": "root0000000000000000000000000000", "name": "root", "depth": 0,
                 "delegation_reason": null, "team_id": null},
                {"id": agent_id, "name": "child", "depth": 1,
                 "delegation_reason": "orchestrate", "team_id": "team-alpha"}
            ]
        })))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "topology", "lineage", agent_id])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "stdout should not be empty");
}

#[tokio::test]
async fn e2e_topology_stats() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/topology/stats"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "total_agents": 15,
            "root_agent_count": 3,
            "max_depth": 4,
            "active_count": 12,
            "suspended_count": 2,
            "deregistered_count": 1,
            "team_count": 2,
            "team_sizes": {"team-alpha": 8, "team-beta": 4},
            "depth_histogram": {"0": 3, "1": 7, "2": 5},
            "team_size_histogram": {"4": 1, "8": 1},
            "spawn_count_histogram": {"0": 8, "2": 4, "4": 1},
            "orphan_count": 2,
            "avg_children_per_parent": 2.5
        })))
        .mount(&server)
        .await;

    let output = Command::cargo_bin("aasm")
        .unwrap()
        .args(["--api-url", &server.uri(), "topology", "stats"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(!output.is_empty(), "stdout should not be empty");
}
