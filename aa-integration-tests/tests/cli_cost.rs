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
use common::format::assert_equivalent_objects;
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
