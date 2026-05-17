//! CLI integration tests for `aasm status` (AAASM-1466 / F121 ST-10).
//!
//! Exercises the `aasm status` top-level command — the kubectl-style fleet
//! overview that aggregates runtime health, active agents, pending approvals,
//! and budget into a single render — against a live in-process gateway booted
//! via `CliFixture`.
//!
//! ## Surface vs. AC
//!
//! The ticket description (AAASM-1466) referenced an `aasm status --component
//! {fleet|agents|approvals|budget}` filter and a populated-state test that
//! seeds alerts + cost samples. Both deviate from source today:
//!
//! * `--component` does not exist on `StatusArgs` (`aa-cli/src/commands/status/
//!   mod.rs` declares only `--watch`). The 5 `--component` tests are dropped;
//!   the PR description proposes a follow-up Subtask if the flag is wanted.
//! * The AC explicitly restricts new shared infra to **only** `seed_approval`.
//!   The populated-state test therefore seeds agents + approvals only; alert /
//!   cost coverage is deferred to a future Phase B ST that introduces both
//!   helpers together.
//!
//! Net = 9 tests across happy path, per-output format (×3), JSON↔YAML
//! equivalence, populated state, exit codes 1 and 2, and a `--watch` smoke.

mod common;

use common::cli::CliFixture;

// =============================================================================
// aasm status
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn status_happy_path_empty_gateway_exits_zero_and_renders_all_sections() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .arg("status")
        .output()
        .expect("aasm status should execute");

    assert!(
        out.status.success(),
        "empty gateway should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RUNTIME HEALTH"),
        "missing RUNTIME HEALTH section:\n{stdout}"
    );
    assert!(
        stdout.contains("ACTIVE AGENTS"),
        "missing ACTIVE AGENTS section:\n{stdout}"
    );
    assert!(
        stdout.contains("PENDING APPROVALS"),
        "missing PENDING APPROVALS section:\n{stdout}",
    );
    assert!(
        stdout.contains("BUDGET STATUS"),
        "missing BUDGET STATUS section:\n{stdout}"
    );
}
