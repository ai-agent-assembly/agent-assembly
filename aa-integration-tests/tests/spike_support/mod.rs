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

/// Locate the real `claude` binary, or explain the skip.
///
/// CI runs on Linux, where the binary does not exist. Every scenario that needs
/// it calls this first and returns early on `None` — printing the reason, so a
/// skip is visible in test output rather than looking like a silent pass.
///
/// `AA_SPIKE_CLAUDE_BIN` overrides the PATH lookup.
pub fn require_claude() -> Option<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("AA_SPIKE_CLAUDE_BIN") {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
        println!(
            "SKIP: AA_SPIKE_CLAUDE_BIN points at a path that does not exist: {}",
            path.display()
        );
        return None;
    }
    let out = std::process::Command::new("which").arg("claude").output().ok()?;
    if !out.status.success() {
        println!("SKIP: claude binary not found on PATH (expected on Linux CI)");
        return None;
    }
    let path = std::path::PathBuf::from(std::str::from_utf8(&out.stdout).ok()?.trim());
    if !path.exists() {
        println!("SKIP: claude binary not found on PATH (expected on Linux CI)");
        return None;
    }
    Some(path)
}

/// Skip guard for scenarios that are macOS-specific.
pub fn require_macos() -> bool {
    if cfg!(target_os = "macos") {
        true
    } else {
        println!("SKIP: scenario is macOS-only; this host is {}", std::env::consts::OS);
        false
    }
}

/// Report the real `claude` version, when the binary is present.
pub fn claude_version(bin: &std::path::Path) -> Option<String> {
    let out = std::process::Command::new(bin).arg("--version").output().ok()?;
    Some(std::str::from_utf8(&out.stdout).ok()?.trim().to_owned())
}
