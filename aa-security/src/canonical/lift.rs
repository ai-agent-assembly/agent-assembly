//! Lifting a scanner finding into its canonical form.
//!
//! This is a pure projection. It reads a [`CredentialFinding`] and returns a
//! [`CanonicalFinding`] describing the same detection in provider-neutral terms;
//! it does not scan, does not allocate, and is not called by the scanner. The
//! fast path ADR 0032 §1 protects is untouched by design — nothing in
//! `scanner.rs` gains a call to this module.
//!
//! The severity, confidence and method a canonical finding carries are all
//! derived from the kind, so there is exactly one source of truth per axis.
//! Severity in particular is read back from
//! [`CredentialKind::severity`](crate::scanner::CredentialKind::severity), the
//! same value `GET /api/v1/scrub/patterns` publishes, rather than re-classified
//! here — a second severity table would drift from the published one.

use super::{
    ByteSpan, CanonicalCategory, CanonicalFinding, ConfidenceBand, DetectionMethod, FindingStatus, Provenance, Severity,
};
use crate::scanner::{CredentialFinding, CredentialKind};

/// The recognizer identity carried by every finding the built-in scanner
/// produces.
///
/// Versioned with the crate, because the scanner's behaviour is versioned with
/// the crate: a finding recorded under `0.0.1-rc.6` was produced by that
/// release's detectors and its entropy gate, and a later re-scan of the same
/// bytes may legitimately differ.
pub const SCANNER_PROVENANCE: Provenance = Provenance::new("aa-security::scanner", env!("CARGO_PKG_VERSION"));

impl DetectionMethod {
    /// How the built-in scanner detects this kind.
    ///
    /// The split mirrors `CredentialKind::priority`, which the scanner already
    /// uses to decide which label survives when two detectors overlap: the
    /// generic backstops it ranks lowest are exactly the heuristic ones.
    pub const fn for_credential_kind(kind: &CredentialKind) -> Self {
        match kind {
            // Entropy and shape, not identity.
            CredentialKind::GenericHighEntropy => Self::Heuristic,
            // A permissive address grammar over free text; it recognises the
            // shape of an address, not that one exists.
            CredentialKind::EmailAddress => Self::Heuristic,
            // Written by an operator into the active policy document.
            CredentialKind::Custom => Self::PolicyDefined,
            // Literal prefixes, PEM headers, fixed digit formats and checksums:
            // the match is structurally exact even where it is not certain the
            // matched value is real.
            _ => Self::Deterministic,
        }
    }
}

impl ConfidenceBand {
    /// How much the built-in scanner's detection of this kind can be trusted.
    ///
    /// `CreditCardLuhn` and `SsnPattern` are `Medium` despite being
    /// deterministic matches, and that is the point of having two axes: a Luhn
    /// check admits roughly one in ten random digit strings, and the SSN
    /// detector has no checksum at all, so a structurally exact match is still
    /// a guess about intent. ADR 0032's accepted-risks section states this
    /// residual for locale recognizers; it is equally true of these two.
    pub const fn for_credential_kind(kind: &CredentialKind) -> Self {
        match kind {
            CredentialKind::GenericHighEntropy => Self::Low,
            CredentialKind::EmailAddress | CredentialKind::CreditCardLuhn | CredentialKind::SsnPattern => Self::Medium,
            // An operator-authored pattern is an explicit assertion about their
            // own data, so it is not second-guessed here.
            _ => Self::High,
        }
    }
}

impl Severity {
    /// The severity the scanner already publishes for this kind.
    ///
    /// Falls back to [`Severity::Critical`] if the published label is ever
    /// something other than the four known levels. That branch is unreachable
    /// today — `CredentialKind::severity` returns one of four literals — and it
    /// fails closed rather than open on purpose: an unclassifiable finding must
    /// not become a low-severity one (ADR 0032 §5).
    pub fn for_credential_kind(kind: &CredentialKind) -> Self {
        Self::from_label(kind.severity()).unwrap_or(Self::Critical)
    }
}

impl From<&CredentialFinding> for CanonicalFinding {
    /// Describe a scanner finding in canonical terms.
    ///
    /// Total: every [`CredentialFinding`] has a canonical form, because the
    /// category mapping is exhaustive over `CredentialKind`. Lossless in the
    /// direction that matters — the kind is recoverable from the category, so
    /// the original redaction label can always be reconstructed.
    fn from(finding: &CredentialFinding) -> Self {
        let confidence = ConfidenceBand::for_credential_kind(&finding.kind);
        Self {
            category: CanonicalCategory::from_credential_kind(&finding.kind),
            severity: Severity::for_credential_kind(&finding.kind),
            confidence,
            span: ByteSpan::new(finding.offset, finding.end()),
            method: DetectionMethod::for_credential_kind(&finding.kind),
            provenance: SCANNER_PROVENANCE,
            // A detection the recognizer cannot be wrong about is `Confirmed`;
            // anything the recognizer itself rates lower is a real finding from
            // a source that can be wrong about it, which is `Suspected`. Note
            // that neither means "clean" — no status does (ADR 0032 §5).
            status: match confidence {
                ConfidenceBand::High => FindingStatus::Confirmed,
                ConfidenceBand::Medium | ConfidenceBand::Low => FindingStatus::Suspected,
            },
        }
    }
}
