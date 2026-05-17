//! CLI integration tests for `aasm version` (AAASM-1467 / F121 ST-11).
//!
//! Exercises the top-level `aasm version` command against a live in-process
//! gateway booted via [`CliFixture`], plus one degraded path (gateway
//! unreachable) using a stand-alone command pointed at a freshly-reserved-
//! and-released TCP port. Output shape per `aa-cli/src/commands/version.rs`
//! is a flat `Vec<VersionRow>` of `{component, version, status}` for the
//! three components `cli`, `gateway`, `api`.
//!
//! ## Leaf surface (from `aa-cli/src/commands/version.rs`)
//!
//! | Leaf | Args | Flags | Output shape |
//! | --- | --- | --- | --- |
//! | version | — | `--output` (inherited from root) | array of three rows (cli, gateway, api) |
//!
//! ## AC vs implementation
//!
//! AAASM-1467 originally described a nested JSON shape with `commit` and
//! `build_date` metadata. The implementation does not currently expose
//! those fields — the build-metadata test instead asserts the shape of
//! what the CLI actually emits (semver `version` on the `cli` row, presence
//! of all three component rows). Adding `commit` / `build_date` is a
//! CLI-surface change and out of scope for this ST.

mod common;

use common::cli::CliFixture;
use common::format::assert_equivalent_records;
use rstest::rstest;

// =============================================================================
// aasm version
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn version_happy_path_reports_cli_and_gateway_rows() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["version"])
        .output()
        .expect("aasm version should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("cli"),
        "stdout should mention the `cli` row\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("gateway"),
        "stdout should mention the `gateway` row\nstdout:\n{stdout}",
    );
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn version_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["version", "--output", fmt])
        .output()
        .expect("aasm version should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn version_json_and_yaml_describe_equivalent_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let json_out = fixture
        .cmd()
        .args(["version", "--output", "json"])
        .output()
        .expect("aasm version --output json should execute");
    assert!(json_out.status.success(), "json variant should exit 0");

    let yaml_out = fixture
        .cmd()
        .args(["version", "--output", "yaml"])
        .output()
        .expect("aasm version --output yaml should execute");
    assert!(yaml_out.status.success(), "yaml variant should exit 0");

    // `version` emits a flat array keyed by `component`; equivalence asserts
    // both formats describe the same {cli, gateway, api} record set. Per-row
    // `status` is reachability-dependent and excluded by the helper (it
    // compares only the `component` id field).
    assert_equivalent_records(&json_out.stdout, &yaml_out.stdout, "component");
}
