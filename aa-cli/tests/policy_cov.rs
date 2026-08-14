//! Integration tests for `aasm policy` HTTP-backed subcommands (AAASM-3804).
//!
//! Covers `policy list`, `policy get` (active, served by the gateway), and
//! `policy show` (capabilities + budget rollup), including the documented
//! exit-code mapping (`2` nothing-to-show, `4` agent-not-found, `3` bad-request).
//! The filesystem-backed paths (`history`, `rollback`, `diff`, `get --version`,
//! `simulate`) already have in-crate unit tests and are not re-covered here.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::policy::get::{self, GetArgs};
use aa_cli::commands::policy::list::{self, ListArgs};
use aa_cli::commands::policy::show::{self, ShowArgs};
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

// ── policy list ───────────────────────────────────────────────────────

async fn mount_policies(server: &MockServer, items: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/policies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "items": items, "page": 1, "per_page": 20, "total": 2
        })))
        .mount(server)
        .await;
}

fn run_list(uri: String, fmt: OutputFormat) -> ExitCode {
    std::thread::spawn(move || list::run(ListArgs {}, &make_context(&uri), fmt))
        .join()
        .unwrap()
}

#[tokio::test]
async fn list_table_json_yaml_succeed() {
    let server = MockServer::start().await;
    mount_policies(
        &server,
        serde_json::json!([
            {"name": "abc123", "version": "2026-04-30T10:00:00Z", "active": true, "rule_count": 5},
            {"name": "def456", "version": "2026-04-29T08:00:00Z", "active": false, "rule_count": 3}
        ]),
    )
    .await;
    let uri = server.uri();
    for fmt in [OutputFormat::Table, OutputFormat::Json, OutputFormat::Yaml] {
        assert_eq!(run_list(uri.clone(), fmt), ExitCode::SUCCESS);
    }
}

#[tokio::test]
async fn list_empty_succeeds() {
    let server = MockServer::start().await;
    mount_policies(&server, serde_json::json!([])).await;
    assert_eq!(run_list(server.uri(), OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn list_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    assert_eq!(run_list(server.uri(), OutputFormat::Table), ExitCode::FAILURE);
}

// ── policy get (active) ───────────────────────────────────────────────

#[tokio::test]
async fn get_active_prints_yaml_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies/active"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy_yaml": "tier: low\nrules: []\n"
        })))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || get::run(GetArgs { version: None }, &make_context(&server.uri())))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn get_active_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/policies/active"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let result = std::thread::spawn(move || get::run(GetArgs { version: None }, &make_context(&server.uri())))
        .join()
        .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}

// ── policy show ───────────────────────────────────────────────────────

fn run_show(uri: String, args: ShowArgs, fmt: OutputFormat) -> ExitCode {
    std::thread::spawn(move || show::run(args, &make_context(&uri), fmt))
        .join()
        .unwrap()
}

#[tokio::test]
async fn show_without_flags_returns_exit_code_2() {
    // No HTTP call is made; the guard short-circuits before the runtime.
    let args = ShowArgs {
        agent_id: "aabbccdd00112233aabbccdd00112233".to_string(),
        show_permissions: false,
        show_budget: false,
    };
    assert_eq!(
        run_show("http://127.0.0.1:1".to_string(), args, OutputFormat::Table),
        ExitCode::from(2u8)
    );
}

#[tokio::test]
async fn show_permissions_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb/capabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "allow": ["file_read"],
            "deny": ["network_outbound"],
            "sources": [
                {"scope": "global", "allow": ["file_read", "file_write"], "deny": []},
                {"scope": "team:platform", "allow": ["file_read"], "deny": ["network_outbound"]}
            ]
        })))
        .mount(&server)
        .await;
    let args = ShowArgs {
        agent_id: "aabb".to_string(),
        show_permissions: true,
        show_budget: false,
    };
    assert_eq!(run_show(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn show_budget_json_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb/budget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "rows": [
                {"scope": "agent", "period": "daily", "spent_usd": "12.50", "limit_usd": "50.00", "remaining_usd": "37.50", "percent_used": 25.0}
            ]
        })))
        .mount(&server)
        .await;
    let args = ShowArgs {
        agent_id: "aabb".to_string(),
        show_permissions: false,
        show_budget: true,
    };
    assert_eq!(run_show(server.uri(), args, OutputFormat::Json), ExitCode::SUCCESS);
}

#[tokio::test]
async fn show_both_permissions_and_budget_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb/capabilities"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "allow": [], "deny": [], "sources": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/aabb/budget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "rows": [] })))
        .mount(&server)
        .await;
    let args = ShowArgs {
        agent_id: "aabb".to_string(),
        show_permissions: true,
        show_budget: true,
    };
    assert_eq!(run_show(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn show_permissions_404_returns_exit_code_4() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/ghost/capabilities"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let args = ShowArgs {
        agent_id: "ghost".to_string(),
        show_permissions: true,
        show_budget: false,
    };
    assert_eq!(run_show(server.uri(), args, OutputFormat::Table), ExitCode::from(4u8));
}

#[tokio::test]
async fn show_permissions_400_returns_exit_code_3() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agents/bad/capabilities"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let args = ShowArgs {
        agent_id: "bad".to_string(),
        show_permissions: true,
        show_budget: false,
    };
    assert_eq!(run_show(server.uri(), args, OutputFormat::Table), ExitCode::from(3u8));
}
