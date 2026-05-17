//! CLI integration tests for `aasm cost` (AAASM-1470 / F121 ST-14).
//!
//! Exercises the `cost summary` and `cost forecast` leaves against a live
//! in-process gateway booted via [`CliFixture`]. Spend state is seeded
//! directly into the gateway's `BudgetTracker` via
//! [`CliFixture::seed_cost_sample`] — the gateway exposes no HTTP route
//! for recording cost samples, so direct insertion is the test-only
//! equivalent (same pattern as registry + trace-store seeding).
//!
//! ## Leaf surface (from `aa-cli/src/commands/cost/`)
//!
//! | Leaf | Args | Flags | Output shape |
//! | --- | --- | --- | --- |
//! | summary | — | `--period {today,month}`, `--group-by agent` | nested `CostSummaryDisplay` |
//! | forecast | — | _(none)_ | nested `CostForecastDisplay` |
//!
//! ## AC vs implementation
//!
//! AAASM-1470 originally described flags `--team`, `--since`, `--until`,
//! `--horizon` that do not exist in the current `aa-cli` cost surface,
//! and a `seed_cost_sample` helper that had to be added by this ST. The
//! tests here cover what the CLI actually exposes today: `--period`,
//! `--group-by agent`, structural forecast assertions, and cross-format
//! equivalence. Missing flags would be CLI-surface changes outside the
//! scope of an integration-test ST.

mod common;

use common::cli::CliFixture;
use common::format::{assert_equivalent_objects, parse_json};
use rstest::rstest;

// =============================================================================
// aasm cost summary
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn cost_summary_happy_path_renders_daily_spend() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["cost", "summary"])
        .output()
        .expect("aasm cost summary should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("COST SUMMARY"),
        "stdout should contain the section header\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("Daily spend"),
        "stdout should mention `Daily spend` for the default --period today\nstdout:\n{stdout}",
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn cost_summary_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["cost", "summary", "--output", fmt])
        .output()
        .expect("aasm cost summary should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_summary_json_and_yaml_describe_equivalent_object() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let json_out = fixture
        .cmd()
        .args(["cost", "summary", "--output", "json"])
        .output()
        .expect("aasm cost summary --output json should execute");
    assert!(json_out.status.success(), "json variant should exit 0");

    let yaml_out = fixture
        .cmd()
        .args(["cost", "summary", "--output", "yaml"])
        .output()
        .expect("aasm cost summary --output yaml should execute");
    assert!(yaml_out.status.success(), "yaml variant should exit 0");

    // `cost summary` emits a single `CostSummaryDisplay` object (not a
    // collection), so structural object-equality is the right check here.
    assert_equivalent_objects(&json_out.stdout, &yaml_out.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_summary_period_month_switches_rendered_label() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["cost", "summary", "--period", "month"])
        .output()
        .expect("aasm cost summary --period month should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Monthly spend"),
        "--period month should render `Monthly spend` instead of `Daily spend`\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("COST SUMMARY (Monthly)"),
        "section header should carry the period label\nstdout:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_summary_group_by_agent_renders_per_agent_table_after_seed() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    // Seed one agent with $8.10 of spend so the per-agent table has at
    // least one row to render. Without seeded spend, `render_agent_table`
    // is skipped (early-return on empty `per_agent`).
    let agent_id = fixture.seed_agents(1)[0];
    fixture.seed_cost_sample(agent_id, Some("topology-it"), "8.10");

    let out = fixture
        .cmd()
        .args(["cost", "summary", "--group-by", "agent"])
        .output()
        .expect("aasm cost summary --group-by agent should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("AGENT_ID"),
        "--group-by agent should render the per-agent table header `AGENT_ID`\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("DAILY_SPEND"),
        "per-agent table should include `DAILY_SPEND` column\nstdout:\n{stdout}",
    );
}

// =============================================================================
// aasm cost forecast
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn cost_forecast_happy_path_renders_projection() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["cost", "forecast"])
        .output()
        .expect("aasm cost forecast should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("COST FORECAST"),
        "stdout should contain the section header\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("Projected monthly"),
        "stdout should mention `Projected monthly` label\nstdout:\n{stdout}",
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn cost_forecast_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["cost", "forecast", "--output", fmt])
        .output()
        .expect("aasm cost forecast should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_forecast_json_and_yaml_describe_equivalent_object() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let json_out = fixture
        .cmd()
        .args(["cost", "forecast", "--output", "json"])
        .output()
        .expect("aasm cost forecast --output json should execute");
    assert!(json_out.status.success(), "json variant should exit 0");

    let yaml_out = fixture
        .cmd()
        .args(["cost", "forecast", "--output", "yaml"])
        .output()
        .expect("aasm cost forecast --output yaml should execute");
    assert!(yaml_out.status.success(), "yaml variant should exit 0");

    // `cost forecast` emits a single `CostForecastDisplay` object (not a
    // collection), so structural object-equality is the right check.
    assert_equivalent_objects(&json_out.stdout, &yaml_out.stdout);
}

#[tokio::test(flavor = "multi_thread")]
async fn cost_forecast_structural_assertion_after_seed() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    // Seed enough spend that the projection is non-trivial. We never assert
    // exact projected numbers (per AC: "Do NOT assert exact numbers — the
    // forecasting algorithm may evolve") — only structural properties.
    let agent_id = fixture.seed_agents(1)[0];
    fixture.seed_cost_sample(agent_id, Some("topology-it"), "12.34");

    let out = fixture
        .cmd()
        .args(["cost", "forecast", "--output", "json"])
        .output()
        .expect("aasm cost forecast --output json should execute");
    assert!(out.status.success(), "should exit 0");

    let v = parse_json(&out.stdout);

    for field in [
        "date",
        "day_of_month",
        "days_in_month",
        "current_daily_spend",
        "projected_monthly_spend",
    ] {
        assert!(
            v.get(field).is_some(),
            "forecast output should expose `{field}` field\nstdout:\n{v}",
        );
    }

    let day_of_month = v["day_of_month"].as_u64().expect("day_of_month should be an integer");
    let days_in_month = v["days_in_month"].as_u64().expect("days_in_month should be an integer");
    assert!(
        (1..=31).contains(&day_of_month),
        "day_of_month should be 1..=31, got {day_of_month}",
    );
    assert!(
        (28..=31).contains(&days_in_month),
        "days_in_month should be 28..=31, got {days_in_month}",
    );

    let projected: f64 = v["projected_monthly_spend"]
        .as_str()
        .expect("projected_monthly_spend should be a string")
        .parse()
        .expect("projected_monthly_spend should parse as f64");
    let current: f64 = v["current_daily_spend"]
        .as_str()
        .expect("current_daily_spend should be a string")
        .parse()
        .expect("current_daily_spend should parse as f64");
    assert!(
        projected >= 0.0,
        "projected_monthly_spend should be non-negative, got {projected}"
    );
    assert!(
        current >= 0.0,
        "current_daily_spend should be non-negative, got {current}"
    );
    // Trivial sanity: projection over a full month should be at least the
    // single-day spend (algorithm-agnostic — anything less means a bug).
    assert!(
        projected >= current,
        "projected_monthly_spend ({projected}) should not be smaller than current_daily_spend ({current})",
    );
}
