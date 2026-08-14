//! Integration tests for `aasm agent` subcommands (AAASM-3804).
//!
//! Drives the HTTP-backed `run()` paths of `agent list`, `agent inspect`, and
//! `agent kill` against a mocked gateway. Each `run()` builds its own tokio
//! runtime, so it is invoked on a dedicated thread.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::agent::inspect::{self, InspectArgs};
use aa_cli::commands::agent::kill::{self, KillArgs};
use aa_cli::commands::agent::list::{self, ListArgs};
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn agent_json(id: &str, name: &str, framework: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "framework": framework,
        "version": "1.0.0",
        "status": status,
        "tool_names": ["search"],
        "metadata": {"env": "test"},
        "pid": 4242,
        "session_count": 3,
        "last_event": "2026-04-30T10:00:00Z",
        "policy_violations_count": 1,
        "active_sessions": [
            {"session_id": "s1", "started_at": "2026-04-30T09:00:00Z", "status": "running"}
        ],
        "recent_events": [
            {"event_type": "violation", "summary": "blocked", "timestamp": "2026-04-30T09:30:00Z"}
        ],
        "recent_traces": [
            {"session_id": "sess-1", "timestamp": "2026-04-30T09:31:00Z"}
        ]
    })
}

async fn mount_agent_list(server: &MockServer, items: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": items, "page": 1, "per_page": 20, "total": 2
        })))
        .mount(server)
        .await;
}

fn run_list(uri: String, args: ListArgs, fmt: OutputFormat) -> ExitCode {
    std::thread::spawn(move || list::run(args, &make_context(&uri), fmt))
        .join()
        .unwrap()
}

// ── agent list ────────────────────────────────────────────────────────

#[tokio::test]
async fn list_table_succeeds() {
    let server = MockServer::start().await;
    mount_agent_list(
        &server,
        serde_json::json!([
            agent_json("aabb", "alpha", "langgraph", "Active"),
            agent_json("ccdd", "beta", "crewai", "Suspended(PolicyViolation)")
        ]),
    )
    .await;
    let args = ListArgs {
        status: None,
        framework: None,
        watch: false,
    };
    assert_eq!(run_list(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_json_and_yaml_succeed() {
    let server = MockServer::start().await;
    mount_agent_list(
        &server,
        serde_json::json!([agent_json("aabb", "alpha", "langgraph", "Active")]),
    )
    .await;
    let uri = server.uri();
    for fmt in [OutputFormat::Json, OutputFormat::Yaml] {
        let args = ListArgs {
            status: None,
            framework: None,
            watch: false,
        };
        assert_eq!(run_list(uri.clone(), args, fmt), ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn list_status_filter_to_empty_prints_no_agents() {
    // The filter matches nothing ⇒ the "No agents found" branch is hit but the
    // command still succeeds.
    let server = MockServer::start().await;
    mount_agent_list(
        &server,
        serde_json::json!([agent_json("aabb", "alpha", "langgraph", "Active")]),
    )
    .await;
    let args = ListArgs {
        status: Some("Deregistered".to_string()),
        framework: None,
        watch: false,
    };
    assert_eq!(run_list(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_framework_filter_matches() {
    let server = MockServer::start().await;
    mount_agent_list(
        &server,
        serde_json::json!([
            agent_json("aabb", "alpha", "langgraph", "Active"),
            agent_json("ccdd", "beta", "crewai", "Active")
        ]),
    )
    .await;
    let args = ListArgs {
        status: None,
        framework: Some("crewai".to_string()),
        watch: false,
    };
    assert_eq!(run_list(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_empty_result_succeeds() {
    let server = MockServer::start().await;
    mount_agent_list(&server, serde_json::json!([])).await;
    let args = ListArgs {
        status: None,
        framework: None,
        watch: false,
    };
    assert_eq!(run_list(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let args = ListArgs {
        status: None,
        framework: None,
        watch: false,
    };
    assert_eq!(run_list(server.uri(), args, OutputFormat::Table), ExitCode::FAILURE);
}

// ── agent inspect ─────────────────────────────────────────────────────

#[tokio::test]
async fn inspect_table_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb"))
        .respond_with(ResponseTemplate::new(200).set_body_json(agent_json("aabb", "alpha", "langgraph", "Active")))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || {
        inspect::run(
            InspectArgs {
                agent_id: "aabb".to_string(),
            },
            &make_context(&server.uri()),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn inspect_json_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb"))
        .respond_with(ResponseTemplate::new(200).set_body_json(agent_json("aabb", "alpha", "custom", "Active")))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || {
        inspect::run(
            InspectArgs {
                agent_id: "aabb".to_string(),
            },
            &make_context(&server.uri()),
            OutputFormat::Json,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn inspect_404_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/ghost"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || {
        inspect::run(
            InspectArgs {
                agent_id: "ghost".to_string(),
            },
            &make_context(&server.uri()),
            OutputFormat::Table,
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── agent kill ────────────────────────────────────────────────────────

#[tokio::test]
async fn kill_force_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/agents/aabb"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || {
        kill::run(
            KillArgs {
                agent_id: "aabb".to_string(),
                force: true,
            },
            &make_context(&server.uri()),
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn kill_force_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/agents/aabb"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || {
        kill::run(
            KillArgs {
                agent_id: "aabb".to_string(),
                force: true,
            },
            &make_context(&server.uri()),
        )
    })
    .join()
    .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}
