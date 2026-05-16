//! Integration tests for the `commands::budget` module — AAASM-1051 F100.
//!
//! Spins up a wiremock server returning a fixture `BudgetRollupResponse`
//! and asserts:
//! - the typed wire-shape round-trips through `fetch_budget_rollup`
//! - the comfy-table text rendering contains the expected per-row layout
//!   with formatted USD strings (`$` prefix, thousands separators), and the
//!   `subtree` row when the agent has descendants
//! - the JSON rendering deserialises back into the same response shape with
//!   matching fields

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use aa_cli::commands::budget::{self, BudgetRollup};
use aa_cli::output::OutputFormat;

const FIXTURE_AGENT_ID: &str = "aabbccdd00112233aabbccdd00112233";

fn make_context(api_url: &str) -> aa_cli::config::ResolvedContext {
    aa_cli::config::ResolvedContext {
        name: None,
        api_url: api_url.to_string(),
        api_key: None,
    }
}

fn fixture_response_json() -> serde_json::Value {
    // Stands in for the AAASM-1051 fixture registry+policy bundle:
    //   agent has a $50/day limit, spent $12.50 (25%)
    //   team:eng-platform has no limit, has spent $12,500.00
    //   org has $200/day limit, spent $87.25 (43.6%)
    //   agent has descendants, subtree today total $250.00
    // Wire strings are already round_dp(2) by the server (commit 1 of this PR).
    serde_json::json!({
        "rows": [
            {
                "scope": "agent",
                "period": "daily",
                "spent_usd": "12.50",
                "limit_usd": "50.00",
                "remaining_usd": "37.50",
                "percent_used": 25.0
            },
            {
                "scope": "team:eng-platform",
                "period": "daily",
                "spent_usd": "12500.00"
            },
            {
                "scope": "org",
                "period": "daily",
                "spent_usd": "87.25",
                "limit_usd": "200.00",
                "remaining_usd": "112.75",
                "percent_used": 43.625
            },
            {
                "scope": "subtree",
                "period": "today",
                "spent_usd": "250.00"
            }
        ]
    })
}

async fn fixture_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{FIXTURE_AGENT_ID}/budget")))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture_response_json()))
        .expect(1)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn fetch_returns_typed_response_matching_wire_shape() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let rollup = budget::fetch_budget_rollup(&ctx, FIXTURE_AGENT_ID)
        .await
        .expect("fetch should succeed");

    assert_eq!(rollup.rows.len(), 4);

    assert_eq!(rollup.rows[0].scope, "agent");
    assert_eq!(rollup.rows[0].spent_usd, "12.50");
    assert_eq!(rollup.rows[0].limit_usd.as_deref(), Some("50.00"));
    assert_eq!(rollup.rows[0].remaining_usd.as_deref(), Some("37.50"));
    assert_eq!(rollup.rows[0].percent_used, Some(25.0));

    assert_eq!(rollup.rows[1].scope, "team:eng-platform");
    assert_eq!(rollup.rows[1].limit_usd, None);

    assert_eq!(rollup.rows[2].scope, "org");
    assert_eq!(rollup.rows[2].percent_used, Some(43.625));

    // Subtree row only emitted when agent has descendants.
    assert_eq!(rollup.rows[3].scope, "subtree");
    assert_eq!(rollup.rows[3].period, "today");
    assert_eq!(rollup.rows[3].spent_usd, "250.00");
}

#[tokio::test]
async fn text_output_contains_per_row_table_with_formatted_usd_and_subtree() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let rollup = budget::fetch_budget_rollup(&ctx, FIXTURE_AGENT_ID).await.unwrap();

    let mut buf = Vec::new();
    budget::render_to(&rollup, OutputFormat::Table, &mut buf).unwrap();
    let out = String::from_utf8(buf).unwrap();

    // Comfy-table headers.
    for header in ["Scope", "Period", "Spent", "Limit", "Remaining", "Used %"] {
        assert!(out.contains(header), "missing column header {header}: {out}");
    }

    // Each row's scope label appears at least once.
    assert!(out.contains("agent"), "expected agent row: {out}");
    assert!(out.contains("team:eng-platform"), "expected team row: {out}");
    assert!(out.contains("org"), "expected org row: {out}");
    assert!(out.contains("subtree"), "expected subtree row: {out}");

    // USD formatted with $ prefix and thousands separators (server rounded to 2dp).
    assert!(out.contains("$12.50"), "agent spent should be $12.50: {out}");
    assert!(out.contains("$37.50"), "agent remaining should be $37.50: {out}");
    assert!(out.contains("$12,500.00"), "team spent should have comma: {out}");
    assert!(out.contains("$87.25"), "org spent should be $87.25: {out}");
    assert!(out.contains("$250.00"), "subtree spent should be $250.00: {out}");

    // Percent rendered to 1 decimal.
    assert!(out.contains("25.0%"), "agent should show 25.0%: {out}");
    assert!(out.contains("43.6%"), "org should show 43.6%: {out}");

    // Rows without a limit show the em-dash placeholder.
    assert!(out.contains("—"), "missing-limit row should show — placeholder: {out}");
}

#[tokio::test]
async fn json_output_round_trips_into_typed_schema() {
    let server = fixture_server().await;
    let ctx = make_context(&server.uri());

    let rollup = budget::fetch_budget_rollup(&ctx, FIXTURE_AGENT_ID).await.unwrap();

    let mut buf = Vec::new();
    budget::render_to(&rollup, OutputFormat::Json, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();

    let parsed: BudgetRollup = serde_json::from_str(&s).expect("rendered JSON should parse");
    assert_eq!(parsed.rows.len(), rollup.rows.len());
    for (a, b) in parsed.rows.iter().zip(rollup.rows.iter()) {
        assert_eq!(a.scope, b.scope);
        assert_eq!(a.period, b.period);
        assert_eq!(a.spent_usd, b.spent_usd);
        assert_eq!(a.limit_usd, b.limit_usd);
        assert_eq!(a.remaining_usd, b.remaining_usd);
        assert_eq!(a.percent_used, b.percent_used);
    }
}

#[tokio::test]
async fn fetch_propagates_404_when_agent_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/agents/{FIXTURE_AGENT_ID}/budget")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let ctx = make_context(&server.uri());
    let err = budget::fetch_budget_rollup(&ctx, FIXTURE_AGENT_ID)
        .await
        .expect_err("404 should surface as an error");
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("not found") || msg.contains("404"),
        "got: {msg}"
    );
}
