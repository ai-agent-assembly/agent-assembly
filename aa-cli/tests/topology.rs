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
