//! Integration tests for `aasm topology` subcommands.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

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

// ── topology overview ─────────────────────────────────────────────────

#[tokio::test]
async fn overview_returns_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/topology/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_overview_json()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::overview::OverviewArgs {
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::overview::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn overview_json_output() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/topology/overview"))
        .respond_with(ResponseTemplate::new(200).set_body_json(sample_overview_json()))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::overview::OverviewArgs {
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::overview::run(args, &ctx, OutputFormat::Json)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

// ── topology tree ─────────────────────────────────────────────────────

#[tokio::test]
async fn tree_returns_success() {
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
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::tree::TreeArgs {
            agent_id: root_id.to_string(),
            depth: None,
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::tree::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

// ── topology team ─────────────────────────────────────────────────────

#[tokio::test]
async fn team_returns_success() {
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
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::team::TeamArgs {
            team_id: "team-alpha".to_string(),
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::team::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

// ── topology lineage ──────────────────────────────────────────────────

#[tokio::test]
async fn lineage_returns_success() {
    let server = MockServer::start().await;

    let agent_id = "aabbccdd00112233aabbccdd00112233";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/lineage/{agent_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": agent_id,
            "ancestor_count": 2,
            "ancestors": [
                {"id": "root0000000000000000000000000000", "name": "root", "depth": 0, "delegation_reason": null, "team_id": null},
                {"id": agent_id, "name": "child", "depth": 1, "delegation_reason": "orchestrate", "team_id": "team-alpha"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::lineage::LineageArgs {
            agent_id: agent_id.to_string(),
            show_permissions: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::lineage::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

// ── topology stats ────────────────────────────────────────────────────

#[tokio::test]
async fn stats_returns_success() {
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
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::stats::StatsArgs {};
        let ctx = make_context(&uri);
        aa_cli::commands::topology::stats::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

// ── topology tree error paths ─────────────────────────────────────────

#[tokio::test]
async fn tree_404_returns_exit_code_4() {
    let server = MockServer::start().await;

    let agent_id = "deadbeefdeadbeefdeadbeefdeadbeef";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/tree/{agent_id}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::tree::TreeArgs {
            agent_id: agent_id.to_string(),
            depth: None,
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::tree::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::from(4u8));
}

#[tokio::test]
async fn tree_422_returns_exit_code_5() {
    let server = MockServer::start().await;

    let agent_id = "cafebabecafebabecafebabecafebabe";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/tree/{agent_id}")))
        .respond_with(ResponseTemplate::new(422))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::tree::TreeArgs {
            agent_id: agent_id.to_string(),
            depth: None,
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::tree::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::from(5u8));
}

#[tokio::test]
async fn tree_depth_zero_returns_failure_without_http_call() {
    let server = MockServer::start().await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::tree::TreeArgs {
            agent_id: "anyagentid".to_string(),
            depth: Some(0),
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::tree::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::FAILURE);
}

// ── topology team edge cases ──────────────────────────────────────────

#[tokio::test]
async fn team_empty_returns_success() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/topology/team/empty-team"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "team_id": "empty-team",
            "agent_count": 0,
            "members": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::team::TeamArgs {
            team_id: "empty-team".to_string(),
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::team::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn team_404_returns_exit_code_4() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/topology/team/ghost-team"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::team::TeamArgs {
            team_id: "ghost-team".to_string(),
            status: None,
            show_budget: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::team::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::from(4u8));
}

// ── topology lineage edge cases ───────────────────────────────────────

#[tokio::test]
async fn lineage_root_agent_returns_success() {
    let server = MockServer::start().await;

    let agent_id = "root0000000000000000000000000000";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/lineage/{agent_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "agent_id": agent_id,
            "ancestor_count": 1,
            "ancestors": [
                {"id": agent_id, "name": "root", "depth": 0, "delegation_reason": null, "team_id": null}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::lineage::LineageArgs {
            agent_id: agent_id.to_string(),
            show_permissions: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::lineage::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn lineage_404_returns_exit_code_4() {
    let server = MockServer::start().await;

    let agent_id = "ffffffffffffffffffffffffffffffff";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/topology/lineage/{agent_id}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let uri = server.uri();
    let result = std::thread::spawn(move || {
        let args = aa_cli::commands::topology::lineage::LineageArgs {
            agent_id: agent_id.to_string(),
            show_permissions: false,
        };
        let ctx = make_context(&uri);
        aa_cli::commands::topology::lineage::run(args, &ctx, OutputFormat::Table)
    })
    .join()
    .unwrap();

    assert_eq!(result, ExitCode::from(4u8));
}
