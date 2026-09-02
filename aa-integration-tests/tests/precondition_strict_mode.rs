//! Regression coverage for `common::precondition::require` itself
//! (AAASM-5977 AC3).
//!
//! The mechanism this guards is invisible by construction — an unmet
//! precondition either quietly returns `false` or panics, and both outcomes
//! look, from outside, like "the test didn't do much". So this doesn't assert
//! on `require`'s return value directly; it re-execs this same test binary
//! with one environment variable moved and checks the *process outcome* of
//! each arm — a control that moves with the variable under test, not two
//! hand-written constants cross-checking (see AAASM-5977's own falsification
//! requirement: the reverted mechanism must be shown going red).

mod common;

use std::process::Command;

use common::precondition::REQUIRE_ENV;

/// Not a real test — a probe re-exec'd by
/// [`strict_mode_turns_an_unmet_precondition_red`] below. `#[ignore]` keeps
/// it out of a normal `cargo nextest run`; the mechanism test runs just this
/// one via `--exact --ignored`.
///
/// The precondition is forced unmet with a literal `Err` rather than calling
/// a real guard (e.g. `cli_gateway`'s `gateway_binary_available`) — on the
/// machine the AAASM-5977 CI provisioning fix builds the gateway, that real
/// guard would be *met*, both arms below would exit 0, and this test would
/// assert nothing.
#[test]
#[ignore]
fn probe_forced_unmet_precondition() {
    common::precondition::require("probe", Err("forced unmet".to_string()));
}

/// AC3: strict mode turns an unmet precondition into a failing test; without
/// it, the identical unmet precondition is a clean pass. Reverting
/// `require` to unconditionally return `false` (the pre-AAASM-5977 shape)
/// makes the first assertion below fail — this is the negative control the
/// ticket's falsification requirement asks for, expressed as a moved
/// variable rather than a manual revert-and-observe step.
#[test]
fn strict_mode_turns_an_unmet_precondition_red() {
    let exe = std::env::current_exe().expect("nextest test binaries are libtest-compatible executables");
    let args = ["--exact", "probe_forced_unmet_precondition", "--ignored", "--nocapture"];

    // Positive: strict mode arms the panic.
    let strict = Command::new(&exe)
        .args(args)
        .env(REQUIRE_ENV, "1")
        .output()
        .expect("run probe (strict)");
    assert!(
        !strict.status.success(),
        "strict mode must not let an unmet precondition pass cleanly; stdout={}",
        String::from_utf8_lossy(&strict.stdout)
    );
    let strict_out = format!(
        "{}{}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr)
    );
    assert!(
        strict_out.contains("forced unmet"),
        "strict-mode failure should name the precondition reason; got: {strict_out}"
    );

    // Negative control: the SAME binary, the SAME forced-unmet precondition,
    // one variable moved. `env_remove` is load-bearing — in a strict CI lane
    // the parent process already has REQUIRE_ENV set and the child would
    // inherit it, so without this both arms are the positive arm and the
    // control can never go red.
    let lax = Command::new(&exe)
        .args(args)
        .env_remove(REQUIRE_ENV)
        .output()
        .expect("run probe (lax)");
    assert!(
        lax.status.success(),
        "without strict mode the same unmet precondition must be a clean pass (today's dev-machine behaviour); stderr={}",
        String::from_utf8_lossy(&lax.stderr)
    );
    let lax_out = format!(
        "{}{}",
        String::from_utf8_lossy(&lax.stdout),
        String::from_utf8_lossy(&lax.stderr)
    );
    assert!(
        lax_out.contains("SKIP ["),
        "the lax arm should still print the skip line; got: {lax_out}"
    );
}

/// Closes the propagation hole: if `AA_REQUIRE_PRECONDITIONS` silently failed
/// to reach the integration-tests lane (a workflow edit that drops the env
/// block, for instance), strict mode degrades to today's graceful-skip
/// behaviour and the lane stays green — exactly the invisibility AAASM-5977
/// exists to remove. `GITHUB_WORKFLOW` is stamped by GitHub itself from the
/// workflow's `name:` field, not by the step's own `env:` block, so whatever
/// deletion breaks the env var propagation cannot also delete this signal.
///
/// Name verified distinct from the other workflows that also run this crate's
/// tests: `ci.yml` names its workflow "CI", `claude-code-conformance.yml`
/// names its "Claude Code conformance" — neither collides with
/// `integration-tests.yml`'s "Integration tests", so this must not fire
/// there.
#[test]
fn the_integration_lane_arms_the_strict_gate() {
    if std::env::var("GITHUB_WORKFLOW").as_deref() == Ok("Integration tests") {
        assert!(
            std::env::var_os(REQUIRE_ENV).is_some(),
            "the integration-tests.yml lane must set {REQUIRE_ENV}=1 (AAASM-5977) — \
             without it, every precondition-gated test in this lane degrades to a \
             silent skip-as-pass, which is the exact invisibility this ticket exists to remove"
        );
    }
}
