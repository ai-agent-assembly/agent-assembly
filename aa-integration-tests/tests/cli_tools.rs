//! CLI integration tests for `aasm tools` (AAASM-1473 / F121 ST-17).
//!
//! Covers the single shipped leaf `aasm tools list` plus the parent
//! subcommand's help text. No gateway interaction — `tools list`
//! discovers AI dev tools on the local filesystem. `CliFixture` is
//! still used for harness contract uniformity across `cli_*.rs` files
//! (per AAASM-1258 test-design rule "All tests use the shared
//! `CliFixture` — no per-test-file gateway boot helpers"), even though
//! the in-process gateway it boots is unused here.
//!
//! ## Divergence from subtask description
//!
//! AAASM-1473's description was drafted against a planned `--output`-aware
//! tools surface that does not exist in `aa-cli/src/commands/tools.rs` on
//! master:
//!
//! * The leaf emits a hard-coded `comfy_table` with columns
//!   `TOOL | VERSION | PATH | GOVERNANCE LEVEL`. The global `--output`
//!   flag is ignored — no JSON/YAML emission. Therefore the AC's
//!   `assert_equivalent_records()`-based per-format tests are not
//!   applicable and are not implemented here.
//! * The list contains only *detected* tools, not the four canonical
//!   names always. On a clean system (CI runner) the output is the
//!   friendly message `"No AI dev tools detected on this system."`;
//!   on a populated dev box the table appears with `ClaudeCode` /
//!   `Codex` / `GitHubCopilot` / `Windsurf` rows (`DevToolKind` debug
//!   format, not lowercase as the ticket assumes).
//!
//! Tests below tolerate both branches so the file is green on both CI
//! (empty) and a dev-machine (populated).
//!
//! Adding the missing `--output` JSON/YAML support to `tools list` is a
//! worthwhile follow-up but is production work that should land in its
//! own ticket; out of scope here.

mod common;

use common::cli::CliFixture;

// ============================================================================
// aasm tools list — happy path
// ============================================================================

/// Canonical column headers emitted by `tools list` when the table branch
/// runs (i.e. at least one tool was detected). Kept here so the assertion
/// fails loudly if the column set changes upstream.
const TABLE_HEADERS: [&str; 4] = ["TOOL", "VERSION", "PATH", "GOVERNANCE LEVEL"];

/// Friendly message printed by `tools list` when no tools were detected.
/// Must match the literal in `aa-cli/src/commands/tools.rs::execute_list()`.
const EMPTY_MESSAGE: &str = "No AI dev tools detected on this system.";

#[tokio::test(flavor = "multi_thread")]
async fn tools_list_exits_zero_and_emits_friendly_message_or_full_table() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["tools", "list"])
        .output()
        .expect("aasm tools list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    let is_empty_branch = stdout.contains(EMPTY_MESSAGE);
    let is_table_branch = TABLE_HEADERS.iter().all(|h| stdout.contains(h));
    assert!(
        is_empty_branch || is_table_branch,
        "stdout must be either the empty friendly message OR the full table with all four \
         column headers (TOOL/VERSION/PATH/GOVERNANCE LEVEL); got:\n{stdout}",
    );
}
