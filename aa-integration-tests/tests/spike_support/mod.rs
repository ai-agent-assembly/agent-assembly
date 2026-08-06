//! Support fixtures for the AAASM-5276 Spike lifecycle harness.
//!
//! **Spike scaffolding.** Everything here exists to take a measurement the tree
//! cannot take today; AAASM-5278 supersedes it with the production integration
//! model. Nothing here should be promoted verbatim.
//!
//! Safety contract every fixture upholds:
//!
//! * No test writes to, moves or deletes anything under the developer's real
//!   `$HOME/.claude`, `$HOME/.aa`, or `/Library/Application Support/ClaudeCode`.
//! * Config-home redirection is by explicit injection
//!   ([`TempClaudeEnv::adapter`]) or per-child env
//!   ([`proxy_harness::ClaudeLaunch`]), never by mutating process-global state.
//! * The macOS System Keychain is never touched. MitM trust is established via
//!   `NODE_EXTRA_CA_CERTS` pointing at a temp PEM.
//! * `NODE_TLS_REJECT_UNAUTHORIZED` is never set. A TLS failure is a finding.

pub mod mock_anthropic;
pub mod proxy_harness;
pub mod receipt;
pub mod status;
pub mod temp_env;

/// The evidence ledger (AAASM-5465), shared verbatim with `conformance_support`.
///
/// The Spike's two real-binary scenarios decline on exactly the same two
/// preconditions the conformance suite's do, and until AAASM-5465 they declined
/// *silently as far as any machine was concerned* — a printed `SKIP:` line and a
/// green pass. They now write the same record, so one CI summary covers both
/// suites.
///
/// A `use`, not a `mod`: the file is declared once per test binary at its root
/// (`#[path = "evidence/mod.rs"] mod evidence;`), because binaries that include
/// both support directories would otherwise load the same file twice —
/// `clippy::duplicate_mod`.
pub use crate::evidence as outcome;
pub use crate::evidence::Measurement;

pub use mock_anthropic::{
    assert_recorded_and_secret_absent, assert_recorded_and_secret_present, find_secret, AnthropicMock,
    TlsCapturingUpstream,
};
pub use receipt::{Mechanism, SpikeReceipt, AASM_OWNED_SETTINGS_KEYS};
pub use status::{Evidence, HostEnforcement, ProtectionLevel, StatusInputs, StatusReport};
pub use temp_env::{sha256_hex, RealHomeGuard, TempClaudeEnv};

/// The Spike's synthetic secret.
///
/// Matches the deterministic scanner's `sk-ant-` literal pattern
/// (`aa-security/src/scanner.rs:15`, mapping to
/// `CredentialKind::AnthropicKey`) so the redaction path is genuinely
/// exercised, while being unmistakably fabricated: the ticket id is embedded in
/// the token body and the value appears nowhere else on the machine. It is not,
/// and has never been, a credential.
pub const SYNTHETIC_SECRET: &str = "sk-ant-api03-AAASM5276SYNTHETICDONOTUSE0000000000000000000000000000000000AA";

/// Locate the real `claude` binary without declaring anything.
///
/// The non-gating half of the lookup: callers that want the binary as
/// *decoration* (a version string stamped into a receipt) must not print `SKIP`
/// or write a ledger record, because a scenario that measured everything it
/// claims to and merely could not stamp a version has not declined. Before
/// AAASM-5465 the receipt helper called the gating form, so every hermetic
/// scenario in this file printed a `SKIP:` line it had not earned — which is
/// how a skip line stops meaning anything.
///
/// `AA_SPIKE_CLAUDE_BIN` overrides the PATH lookup. Returns the reason on `Err`
/// so the gating form need not re-derive it.
pub fn locate_claude() -> Result<std::path::PathBuf, String> {
    if let Some(explicit) = std::env::var_os("AA_SPIKE_CLAUDE_BIN") {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "AA_SPIKE_CLAUDE_BIN points at a path that does not exist: {}",
            path.display()
        ));
    }
    let absent = || "claude binary not found on PATH (expected on Linux CI)".to_string();
    let out = std::process::Command::new("which")
        .arg("claude")
        .output()
        .map_err(|e| format!("could not run `which claude`: {e}"))?;
    if !out.status.success() {
        return Err(absent());
    }
    let path = std::path::PathBuf::from(std::str::from_utf8(&out.stdout).map_err(|e| e.to_string())?.trim());
    if path.exists() {
        Ok(path)
    } else {
        Err(absent())
    }
}

/// Locate the real `claude` binary, or declare the skip against `scenario`.
///
/// CI runs on Linux, where the binary does not exist. Every scenario that needs
/// it calls this first and returns early on `None` — printing the reason *and*
/// recording it in the [`outcome`] ledger, so the skip is legible to a human
/// reading the log and to the CI step that has to decide whether this lane
/// produced any evidence at all.
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

/// Skip guard for scenarios that are macOS-specific.
///
/// Distinct from [`require_claude`] in the ledger: provisioning cannot fix a
/// Linux runner, so the two need different remedies and must not share a token.
pub fn require_macos(scenario: &str) -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let reason = format!("scenario is macOS-only; this host is {}", std::env::consts::OS);
    println!("SKIP [{scenario}]: {reason}");
    outcome::record(scenario, Measurement::UnsupportedPlatform, &reason);
    false
}

/// Report the real `claude` version, when the binary is present.
pub fn claude_version(bin: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("--version").output().ok()?;
    Some(std::str::from_utf8(&out.stdout).ok()?.trim().to_owned())
}
