//! CLI integration tests for `aasm run` (AAASM-1472 / F121 ST-16).
//!
//! Exercises the `aasm run <tool> [args...]` launcher in `--dry-run` mode
//! against the actual `aa-cli` binary. The companion refactor in
//! `aa-cli/src/commands/run.rs::execute_with_adapters` short-circuits
//! `--dry-run` before `adapter.detect()` and `register_with_gateway()`, so
//! these tests work on CI runners where no AI dev tool is installed and
//! no gateway is reachable.
//!
//! ## Surface vs. AC
//!
//! Three flag-name AC deviations (source-authoritative resolution):
//!
//! * AC says `--tool <name>` — source actually takes the tool as a
//!   positional `<tool>` argument (e.g. `aasm run claude --dry-run`).
//! * AC says `--config <path>` — no such flag exists. No fixture file
//!   created; the per-tool `--config` custom-config test is substituted
//!   by an `--agent-id` override test.
//! * AC says a mutual-exclusion case (`--tool X --command Y`) — no
//!   `--command` flag exists; this test is dropped.
//!
//! Net = 9 tests across help banner, missing-tool clap error, per-tool
//! `--dry-run` (`#[rstest]` × 4), `--agent-id` override, unknown-tool
//! error, and trailing `tool_args` echo.
//!
//! ## Why no `CliFixture`
//!
//! After the dry-run short-circuit refactor, `aasm run --dry-run` makes no
//! HTTP calls and requires no live gateway. Tests construct the
//! `cargo run -p aa-cli --bin aasm -- run …` command by hand.

use std::process::Command;

use rstest::rstest;

/// Build a fresh `cargo run` command for `aasm run …` invocations. Inherits
/// the integration-test crate's cargo so the workspace lockfile is reused.
fn aasm_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["run", "--quiet", "-p", "aa-cli", "--bin", "aasm", "--"]);
    cmd
}

// =============================================================================
// aasm run --help
// =============================================================================

#[test]
fn run_help_exits_zero_and_lists_the_four_supported_tools() {
    let out = aasm_cmd()
        .args(["run", "--help"])
        .output()
        .expect("aasm run --help should execute");

    assert!(
        out.status.success(),
        "run --help should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for tool in ["claude", "codex", "copilot", "windsurf"] {
        assert!(
            stdout.contains(tool),
            "run --help banner should mention `{tool}`:\n{stdout}",
        );
    }
}

#[test]
fn run_without_positional_tool_fails_with_clap_usage_error() {
    let out = aasm_cmd().arg("run").output().expect("aasm run should execute");

    assert!(
        !out.status.success(),
        "run with no tool should fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("Usage"),
        "stderr should surface a clap usage error:\n{stderr}",
    );
}

// =============================================================================
// aasm run <tool> --dry-run
// =============================================================================

#[rstest]
#[case::claude("claude")]
#[case::codex("codex")]
#[case::copilot("copilot")]
#[case::windsurf("windsurf")]
fn run_dry_run_succeeds_for_every_supported_tool(#[case] tool: &str) {
    let out = aasm_cmd()
        .args(["run", tool, "--dry-run"])
        .output()
        .expect("aasm run <tool> --dry-run should execute");

    assert!(
        out.status.success(),
        "{tool} --dry-run should exit 0; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--- aasm run dry-run ---"),
        "{tool} --dry-run should print the dry-run banner:\n{stdout}",
    );
    assert!(
        stdout.contains("--- launch command ---"),
        "{tool} --dry-run should print the launch command section:\n{stdout}",
    );
    assert!(
        stdout.contains(tool),
        "{tool} --dry-run plan should name the tool in the launch command:\n{stdout}",
    );
}

// =============================================================================
// aasm run <unknown>
// =============================================================================

#[test]
fn run_unknown_tool_fails_and_lists_all_supported_tools_on_stderr() {
    let out = aasm_cmd()
        .args(["run", "notathing", "--dry-run"])
        .output()
        .expect("aasm run notathing should execute");

    assert!(
        !out.status.success(),
        "unknown tool should fail; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown tool"),
        "stderr should announce the unknown-tool error:\n{stderr}",
    );
    for tool in ["claude", "codex", "copilot", "windsurf"] {
        assert!(
            stderr.contains(tool),
            "stderr should list `{tool}` among supported tools:\n{stderr}",
        );
    }
}

// =============================================================================
// aasm run --agent-id <id> <tool> --dry-run
// =============================================================================

#[test]
fn run_dry_run_honors_agent_id_override() {
    let custom_id = "cli-it-custom-agent-id";
    let out = aasm_cmd()
        .args(["run", "--agent-id", custom_id, "claude", "--dry-run"])
        .output()
        .expect("aasm run --agent-id should execute");

    assert!(
        out.status.success(),
        "--agent-id override should not affect exit code; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(custom_id),
        "dry-run plan should reflect the explicit --agent-id value:\n{stdout}",
    );
}

// =============================================================================
// aasm run <tool> --dry-run -- <trailing tool_args>
// =============================================================================

#[test]
fn run_dry_run_echoes_trailing_tool_args_in_launch_command() {
    let out = aasm_cmd()
        .args(["run", "claude", "--dry-run", "--", "--some-flag", "value"])
        .output()
        .expect("aasm run with trailing args should execute");

    assert!(
        out.status.success(),
        "trailing args should not affect exit code; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--some-flag") && stdout.contains("value"),
        "launch command section should echo trailing tool_args:\n{stdout}",
    );
}
