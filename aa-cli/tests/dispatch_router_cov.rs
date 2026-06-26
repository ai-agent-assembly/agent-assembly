//! Top-level `commands::dispatch` routing coverage (AAASM-3812).
//!
//! `dispatch_cov.rs` proves a handful of router arms (agent / policy /
//! approvals / audit / proxy-status). The remaining arms — and the small
//! group-`dispatch` shims they delegate to (`alerts::dispatch`,
//! `cost::dispatch`) plus the daemon-free `completion`/`version` handlers —
//! were never driven through the top-level router. Each test parses no CLI;
//! it constructs the `Commands` variant and asserts the router reaches the
//! correct handler (success against a mocked gateway, or the documented
//! graceful-degradation exit for `version`). The per-command tokio runtime
//! is built inside `run()`, so HTTP-backed arms run on a dedicated thread.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::{self, Commands};
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

/// Mount a GET endpoint returning `body`, then route `cmd` through the
/// top-level dispatcher on a dedicated thread and return its exit code.
async fn dispatch_with_get(endpoint: &str, body: serde_json::Value, cmd: Commands) -> ExitCode {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(endpoint.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    let uri = server.uri();
    std::thread::spawn(move || commands::dispatch(cmd, &make_context(&uri), OutputFormat::Table))
        .join()
        .unwrap()
}

#[tokio::test]
async fn dispatch_routes_alerts_list() {
    let cmd = Commands::Alerts(aa_cli::commands::alerts::AlertsArgs {
        command: aa_cli::commands::alerts::AlertsCommands::List(aa_cli::commands::alerts::list::ListArgs {
            agent: None,
            severity: None,
            status: Some("unresolved".to_string()),
        }),
    });
    let body = serde_json::json!({"items": [], "page": 1, "per_page": 20, "total": 0});
    assert_eq!(dispatch_with_get("/api/v1/alerts", body, cmd).await, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_cost_summary() {
    let cmd = Commands::Cost(aa_cli::commands::cost::CostArgs {
        command: aa_cli::commands::cost::CostCommands::Summary(aa_cli::commands::cost::summary::SummaryArgs {
            period: aa_cli::commands::cost::summary::Period::Today,
            group_by: None,
        }),
    });
    let body = serde_json::json!({
        "daily_spend_usd": "1.00",
        "monthly_spend_usd": "10.00",
        "date": "2026-04-15",
        "daily_limit_usd": "50.00",
        "monthly_limit_usd": "500.00",
        "per_agent": []
    });
    assert_eq!(dispatch_with_get("/api/v1/costs", body, cmd).await, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_logs_fetch() {
    let cmd = Commands::Logs(aa_cli::commands::logs::LogsArgs {
        follow: false,
        agent: None,
        r#type: None,
        since: None,
        until: None,
        limit: 50,
        no_color: true,
        output: None,
    });
    let body = serde_json::json!({"items": [], "page": 1, "per_page": 50, "total": 0});
    assert_eq!(dispatch_with_get("/api/v1/logs", body, cmd).await, ExitCode::SUCCESS);
}

#[tokio::test]
async fn dispatch_routes_trace() {
    let sid = "sess-router";
    let cmd = Commands::Trace(aa_cli::commands::trace::TraceArgs {
        session_id: sid.to_string(),
        format: aa_cli::commands::trace::TraceFormat::Tree,
    });
    let body = serde_json::json!({
        "session_id": sid,
        "agent_id": "aabbccdd00112233aabbccdd00112233",
        "spans": [
            {"span_id": "root", "parent_span_id": null, "operation": "llm_call",
             "decision": "allow", "start_time": "2026-01-01T00:00:00Z",
             "end_time": "2026-01-01T00:00:00.800Z"}
        ]
    });
    assert_eq!(
        dispatch_with_get(&format!("/api/v1/traces/{sid}"), body, cmd).await,
        ExitCode::SUCCESS
    );
}

#[tokio::test]
async fn dispatch_routes_topology_overview() {
    let cmd = Commands::Topology(aa_cli::commands::topology::TopologyArgs {
        command: aa_cli::commands::topology::TopologyCommands::Overview(
            aa_cli::commands::topology::overview::OverviewArgs {
                status: None,
                show_budget: false,
            },
        ),
    });
    let body = serde_json::json!({
        "team_count": 0,
        "root_agent_count": 0,
        "total_agent_count": 0,
        "teams": [],
        "standalone_root_agents": []
    });
    assert_eq!(
        dispatch_with_get("/api/v1/topology/overview", body, cmd).await,
        ExitCode::SUCCESS
    );
}

/// `completion` needs no gateway — it writes a shell script to stdout and is
/// routed through the top-level dispatcher here for both a POSIX and a
/// non-POSIX shell.
#[test]
fn dispatch_routes_completion_for_multiple_shells() {
    for shell in [clap_complete::Shell::Bash, clap_complete::Shell::Fish] {
        let cmd = Commands::Completion(aa_cli::commands::completion::CompletionArgs { shell });
        let code = commands::dispatch(cmd, &make_context("http://127.0.0.1:1"), OutputFormat::Table);
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

/// `version` degrades gracefully: against an unreachable gateway it still
/// exits 0 with "unreachable" rows. Routing it through the dispatcher with a
/// dead URL covers the `Commands::Version` arm without a mock server.
#[test]
fn dispatch_routes_version_against_dead_gateway() {
    let code = std::thread::spawn(|| {
        commands::dispatch(
            Commands::Version,
            &make_context("http://127.0.0.1:1"),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
}
