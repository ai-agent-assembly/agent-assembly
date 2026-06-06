//! Advisory, best-effort credential preflight — **non-authoritative**.
//!
//! This module lets the SDK redact obvious credentials locally so an agent can
//! *fail fast* before a secret is ever handed to the transport. It is **not** a
//! security boundary and confers **no** authority:
//!
//! - The SDK is untrusted. The mandatory runtime chokepoint (`aa-runtime`,
//!   AAASM-2568) re-scans, re-redacts, and normalizes **every** event
//!   unconditionally, regardless of anything the SDK did or claims.
//! - Nothing here ever sets a `clean` / `already_scanned` / pre-scanned signal
//!   on the wire. No such marker exists, and the runtime would ignore it if it
//!   did. Preflight only ever *removes* data (redacts); it never adds trust.
//!
//! The scanner is constructed once and reused, mirroring the runtime's
//! precompiled-scanner guardrail.

use aa_security::CredentialScanner;

/// Advisory, best-effort local credential redactor wrapping a precompiled
/// [`CredentialScanner`]. **Non-authoritative** — see the module docs.
pub struct Preflight {
    scanner: CredentialScanner,
}

impl Preflight {
    /// Create a preflight redactor with the default credential scanner.
    pub fn new() -> Self {
        Self {
            scanner: CredentialScanner::new(),
        }
    }

    /// Create a preflight redactor from an explicit scanner configuration.
    pub fn with_scanner(scanner: CredentialScanner) -> Self {
        Self { scanner }
    }

    /// Best-effort redaction of credentials in `input`.
    ///
    /// Returns the input unchanged when no credentials are detected, otherwise
    /// the redacted form. This is **advisory only** — the runtime re-scans
    /// authoritatively, so a miss here is caught there. No trust marker is ever
    /// emitted as a result of this call.
    pub fn advisory_redact(&self, input: String) -> String {
        let scan = self.scanner.scan(&input);
        if scan.is_clean() {
            input
        } else {
            tracing::warn!(
                findings = scan.findings.len(),
                "advisory preflight detected credentials; redacting locally (runtime re-scans authoritatively)"
            );
            scan.redact(&input)
        }
    }
}

impl Default for Preflight {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_input_is_returned_unchanged() {
        let pf = Preflight::new();
        let out = pf.advisory_redact("searched for cats".to_string());
        assert_eq!(out, "searched for cats");
    }

    #[test]
    fn credential_is_redacted() {
        let pf = Preflight::new();
        let secret = "sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab";
        let out = pf.advisory_redact(format!("key is {secret}"));
        assert!(!out.contains("sk-proj-"), "raw credential must not survive, got: {out}");
        assert!(
            out.contains("[REDACTED:"),
            "redacted output should carry a redaction marker"
        );
    }
}
