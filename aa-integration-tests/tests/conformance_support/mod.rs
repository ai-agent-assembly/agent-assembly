//! Fixtures for the Claude Code lifecycle conformance suite (AAASM-5283).
//!
//! # Relationship to the Spike's fixtures
//!
//! AAASM-5276's `spike_support` split into two halves once AAASM-5278 landed the
//! production lifecycle model:
//!
//! * **Instruments** — the MitM proxy driver, the TLS-terminating provider that
//!   records every body it receives, the secret finder, the real-home guard.
//!   These measure the product and are reused here verbatim.
//! * **Stand-ins** — `spike_support::receipt` and `spike_support::status`, which
//!   existed only because there was no production receipt or protection state to
//!   assert against. The Spike's own evidence document records them as
//!   scaffolding that "should not be promoted". They are not used here; the
//!   suite asserts against `aa_core::integration` and the real `EngineLifecycle`.
//!
//! # Safety contract every fixture upholds
//!
//! * No test writes to, moves or deletes anything under the developer's real
//!   `$HOME/.claude`, `$HOME/.aa`, `$HOME/.aasm`, or
//!   `/Library/Application Support/ClaudeCode`.
//! * Root redirection is by explicit injection into `ClaudeCodePaths` and
//!   `ClaudeCodeAdapter::with_overrides`, never by mutating process-global
//!   environment state.
//! * The macOS System Keychain is never touched, and `security add-trusted-cert`
//!   is never run. MitM trust reaches the probe through a temp PEM only.
//! * `NODE_TLS_REJECT_UNAUTHORIZED` is never set. A TLS failure is a finding.

pub mod harness;
pub mod outcome;
pub mod probe;
pub mod proxy;

pub use harness::{walk, ConformanceHarness, HarnessOptions, MEASURED_TOOL_VERSION};
pub use outcome::Measurement;
pub use probe::AdjudicatingProbe;
pub use proxy::RestartableProxy;

/// The synthetic secret every protection scenario carries.
///
/// Re-exported from the adapter so the suite drives the same value the shipped
/// probe does. It matches `aa_security`'s `sk-ant-` literal pattern, so the
/// deterministic scanner genuinely matches it, and is unmistakably fabricated.
pub use aa_devtool_claude_code::probe::SYNTHETIC_SECRET;

/// Assert `needle` appears in none of `surfaces`, naming the surface that
/// leaked.
///
/// Takes the surfaces as `(label, body)` so a failure says *which* artifact
/// carried the value rather than only that something did.
pub fn assert_no_raw_secret(surfaces: &[(String, String)], needle: &str, scenario: &str) {
    for (label, body) in surfaces {
        assert!(
            !body.contains(needle),
            "{scenario}: the raw synthetic secret appeared in `{label}`",
        );
    }
}

/// Print a visible skip and return `false` when this host is not macOS.
///
/// A skip must be legible in the output. A test that quietly returns having
/// asserted nothing is indistinguishable from a pass, which is the failure mode
/// this whole suite exists to rule out.
///
/// The skip is recorded in the [`outcome`] ledger as well as printed, so a lane
/// that exists *to take* this measurement can fail on a skip it never asked
/// for. Recording here rather than at the call site means no opt-out path can
/// forget to declare itself.
pub fn require_macos(scenario: &str) -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let reason = format!("macOS-only scenario; this host is {}", std::env::consts::OS);
    println!("SKIP [{scenario}]: {reason}");
    outcome::record(scenario, Measurement::Skipped, &reason);
    false
}

/// Locate the real `claude` binary, or print why the scenario is skipped.
///
/// `AA_SPIKE_CLAUDE_BIN` overrides the `PATH` lookup, so the optional real-tool
/// CI lane can point at an installation it provisioned itself.
///
/// As with [`require_macos`], the skip is recorded in the [`outcome`] ledger:
/// the real-tool lane provisions the binary itself, so a skip *there* is a
/// broken lane rather than an honest opt-out, and only a machine-readable
/// record makes that difference assertable.
pub fn require_claude(scenario: &str) -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("AA_SPIKE_CLAUDE_BIN") {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
        let reason = format!("AA_SPIKE_CLAUDE_BIN points at {}, which does not exist", path.display());
        println!("SKIP [{scenario}]: {reason}");
        outcome::record(scenario, Measurement::Skipped, &reason);
        return None;
    }
    let found = std::process::Command::new("which")
        .arg("claude")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| std::path::PathBuf::from(s.trim()))
        .filter(|p| p.exists());
    if found.is_none() {
        let reason = "no `claude` binary on PATH (expected on Linux CI); set AA_SPIKE_CLAUDE_BIN to opt in";
        println!("SKIP [{scenario}]: {reason}");
        outcome::record(scenario, Measurement::Skipped, reason);
    }
    found
}

/// Read a workspace-relative source file.
///
/// Used by the assertions that pin a *shipped constant* the suite cannot reach
/// from this crate — the CLI's exit-code mapping being the one that matters, see
/// the known-limitation scenario.
pub fn read_repo_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aa-integration-tests always has a workspace-root parent")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()))
}
