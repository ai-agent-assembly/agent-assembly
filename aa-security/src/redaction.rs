//! Redaction primitive: the credential-scanner output attached to a governance
//! event before it is forwarded or written to the audit log.

use crate::scanner::CredentialFinding;

/// Optional credential-redaction artefacts produced by a credential-scanner pass.
///
/// Populated when an enforcement layer ran the [`CredentialScanner`](crate::scanner::CredentialScanner)
/// and produced at least one finding. Both fields default to empty / `None`,
/// matching the legacy code path that constructs audit entries without scanner
/// output. `Redaction::default()` carries no findings, so consumers can treat it
/// as "scan was clean / not run" without special-casing.
///
/// ## Security invariant
///
/// Neither field stores the raw secret value. `credential_findings` holds only
/// the [`CredentialKind`](crate::scanner::CredentialKind), byte offset, and the
/// `[REDACTED:<kind>]` label (`CredentialFinding`'s `end` field is
/// `#[serde(skip)]`). `redacted_payload` holds the sanitised payload returned by
/// [`ScanResult::redact`](crate::scanner::ScanResult::redact) where every match
/// has been replaced with its `[REDACTED:<kind>]` label.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Redaction {
    /// All credential / PII findings detected by the scanner. Empty when the
    /// scanner found nothing.
    pub credential_findings: Vec<CredentialFinding>,
    /// The redacted version of the action payload (raw secret bytes replaced
    /// with `[REDACTED:<kind>]` labels). `None` when no findings were produced.
    pub redacted_payload: Option<String>,
}
