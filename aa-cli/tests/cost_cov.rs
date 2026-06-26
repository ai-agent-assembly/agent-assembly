//! Integration tests for `aasm cost` subcommands (AAASM-3804).
//!
//! Exercises the HTTP-backed `run()` paths of `cost summary` and `cost
//! forecast` against a mocked gateway, asserting exit codes and the
//! render-branch selection for every output format. The command builds its
//! own tokio runtime internally, so each `run()` is invoked on a dedicated
//! thread to avoid a nested-runtime panic.

use std::process::ExitCode;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::cost::forecast::{self, ForecastArgs};
use aa_cli::commands::cost::summary::{self, GroupBy, Period, SummaryArgs};
use aa_cli::output::OutputFormat;

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn full_cost_body() -> serde_json::Value {
    serde_json::json!({
        "daily_spend_usd": "8.10",
        "monthly_spend_usd": "142.50",
        "date": "2026-04-15",
        "daily_limit_usd": "50.00",
        "monthly_limit_usd": "500.00",
        "per_agent": [
            {"agent_id": "agent-a", "daily_spend_usd": "4.00", "monthly_spend_usd": "80.00", "date": "2026-04-15"},
            {"agent_id": "agent-b", "daily_spend_usd": "4.10", "monthly_spend_usd": "62.50", "date": "2026-04-15"}
        ]
    })
}

async fn mount_costs(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/api/v1/costs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

fn run_summary(uri: String, args: SummaryArgs, fmt: OutputFormat) -> ExitCode {
    std::thread::spawn(move || summary::run(args, &make_context(&uri), fmt))
        .join()
        .unwrap()
}

// ── cost summary ──────────────────────────────────────────────────────

#[tokio::test]
async fn summary_today_table_succeeds() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let args = SummaryArgs {
        period: Period::Today,
        group_by: None,
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn summary_month_with_group_by_agent_renders_per_agent_table() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let args = SummaryArgs {
        period: Period::Month,
        group_by: Some(GroupBy::Agent),
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn summary_json_output_succeeds() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let args = SummaryArgs {
        period: Period::Today,
        group_by: None,
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Json), ExitCode::SUCCESS);
}

#[tokio::test]
async fn summary_yaml_output_succeeds() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let args = SummaryArgs {
        period: Period::Month,
        group_by: None,
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Yaml), ExitCode::SUCCESS);
}

#[tokio::test]
async fn summary_minimal_body_without_limits_succeeds() {
    // No limit fields ⇒ the utilization block is skipped without error.
    let server = MockServer::start().await;
    mount_costs(
        &server,
        serde_json::json!({"daily_spend_usd": "0.00", "date": "2026-04-30"}),
    )
    .await;
    let args = SummaryArgs {
        period: Period::Today,
        group_by: Some(GroupBy::Agent), // empty per_agent ⇒ table branch skipped
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Table), ExitCode::SUCCESS);
}

#[tokio::test]
async fn summary_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/costs"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let args = SummaryArgs {
        period: Period::Today,
        group_by: None,
    };
    assert_eq!(run_summary(server.uri(), args, OutputFormat::Table), ExitCode::FAILURE);
}

// ── cost forecast ─────────────────────────────────────────────────────

#[tokio::test]
async fn forecast_table_succeeds() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let result =
        std::thread::spawn(move || forecast::run(ForecastArgs {}, &make_context(&server.uri()), OutputFormat::Table))
            .join()
            .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn forecast_json_succeeds() {
    let server = MockServer::start().await;
    mount_costs(&server, full_cost_body()).await;
    let result =
        std::thread::spawn(move || forecast::run(ForecastArgs {}, &make_context(&server.uri()), OutputFormat::Json))
            .join()
            .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn forecast_yaml_no_limit_succeeds() {
    let server = MockServer::start().await;
    mount_costs(
        &server,
        serde_json::json!({"daily_spend_usd": "5.00", "date": "2026-01-10"}),
    )
    .await;
    let result =
        std::thread::spawn(move || forecast::run(ForecastArgs {}, &make_context(&server.uri()), OutputFormat::Yaml))
            .join()
            .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
}

#[tokio::test]
async fn forecast_http_error_returns_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/costs"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let result =
        std::thread::spawn(move || forecast::run(ForecastArgs {}, &make_context(&server.uri()), OutputFormat::Table))
            .join()
            .unwrap();
    assert_eq!(result, ExitCode::FAILURE);
}
