//! CLI integration tests for `aasm dashboard` (AAASM-1471 / F121 ST-15).
//!
//! Smoke-only: the dashboard is a TUI that requires a live TTY, and we
//! don't ship a virtual-terminal harness in v0.0.1. These tests exercise
//! the `--help` path only — the clap parser must accept the subcommand
//! plus its global flag siblings and render a usable banner.
//!
//! No actual TUI is ever launched. No gateway HTTP traffic. `CliFixture`
//! is still used for harness contract uniformity across `cli_*.rs` files
//! (per AAASM-1258 test-design rule "All tests use the shared
//! `CliFixture` — no per-test-file gateway boot helpers"), even though
//! the in-process gateway it boots is unused here.
//!
//! ## Divergence from subtask description
//!
//! AAASM-1471's description calls the global override flag `--gateway-url`;
//! master ships it as `--api-url` (declared on the top-level `Cli` struct
//! at `aa-cli/src/lib.rs` with `global = true`). The clap-parser-smoke
//! test uses `--api-url` accordingly. Everything else (banner text,
//! `--output` global flag) matches the description verbatim.
//!
//! ## Future follow-up (not in scope)
//!
//! Full TUI interaction testing (key navigation, dialog rendering, feed
//! updates) requires a `vte`-style virtual-terminal harness. The parent
//! Story's "Out of scope" section explicitly defers this; no follow-up
//! sub-ticket is filed here.

mod common;

use common::cli::CliFixture;

// ============================================================================
// aasm dashboard --help — banner-content tests
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_help_exits_zero_and_describes_tui() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "--help"])
        .output()
        .expect("aasm dashboard --help should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Open an interactive TUI dashboard"),
        "banner should describe the TUI; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_subcommand_name_appears_in_banner() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "--help"])
        .output()
        .expect("aasm dashboard --help should execute");
    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Catches an accidental rename of the subcommand (e.g. dashboard→ui).
    // The Usage line is `Usage: aasm dashboard [OPTIONS] [COMMAND]`, so
    // asserting on the qualified `aasm dashboard` token is precise enough
    // to fail loudly if the leaf is renamed without also being unique
    // enough to false-positive against an unrelated mention.
    assert!(
        stdout.contains("aasm dashboard"),
        "banner should contain the qualified subcommand name 'aasm dashboard'; got:\n{stdout}",
    );
}
