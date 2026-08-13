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
pub mod probe;
pub mod proxy;

/// The evidence ledger (AAASM-5465), re-exported under its historical name.
///
/// A `use`, not a `mod`: the file lives at `tests/evidence/mod.rs` and is
/// declared **once per test binary**, because several suites include both this
/// support directory and `spike_support`, and two `#[path]` declarations of one
/// file in a single binary is `clippy::duplicate_mod`. Every including binary
/// therefore carries `#[path = "evidence/mod.rs"] mod evidence;` at its root.
pub use crate::evidence as outcome;
pub use crate::evidence::Measurement;

pub use harness::{walk, ConformanceHarness, HarnessOptions, MEASURED_TOOL_VERSION};
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
///
/// Recorded as [`Measurement::UnsupportedPlatform`] rather than a generic skip:
/// no amount of provisioning on *this* runner would change the answer, which is
/// the opposite of what [`require_claude`] reports and needs a different fix.
pub fn require_macos(scenario: &str) -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let reason = format!("macOS-only scenario; this host is {}", std::env::consts::OS);
    println!("SKIP [{scenario}]: {reason}");
    outcome::record(scenario, Measurement::UnsupportedPlatform, &reason);
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
///
/// Recorded as [`Measurement::ToolAbsent`], which is the outcome a CI lane can
/// act on — install the binary, or fix the `AA_SPIKE_CLAUDE_BIN` it already set.
pub fn require_claude(scenario: &str) -> Option<std::path::PathBuf> {
    match locate_claude() {
        Ok(path) => Some(path),
        Err(reason) => {
            println!("SKIP [{scenario}]: {reason}");
            outcome::record(scenario, Measurement::ToolAbsent, &reason);
            None
        }
    }
}

/// Locate the real `claude` binary without declaring anything.
///
/// The counterpart to [`require_claude`] for callers that want the binary as
/// *decoration* — a version string in a receipt, say — rather than as a
/// precondition. Those callers must not print `SKIP` or write a ledger record:
/// a scenario that measured everything it claims to measure, and merely could
/// not stamp a version, is not a scenario that declined, and reporting it as one
/// makes every genuine skip line less believable.
///
/// Returns the reason it could not be found on `Err`, so a caller that *is*
/// gating on it does not have to re-derive the message.
pub fn locate_claude() -> Result<std::path::PathBuf, String> {
    if let Some(explicit) = std::env::var_os("AA_SPIKE_CLAUDE_BIN") {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "AA_SPIKE_CLAUDE_BIN points at {}, which does not exist",
            path.display()
        ));
    }
    std::process::Command::new("which")
        .arg("claude")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| std::path::PathBuf::from(s.trim()))
        .filter(|p| p.exists())
        .ok_or_else(|| {
            "no `claude` binary on PATH (expected on Linux CI); set AA_SPIKE_CLAUDE_BIN to opt in".to_string()
        })
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
