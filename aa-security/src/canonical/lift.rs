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

/// Why a [`CredentialFinding`] could not be lifted into a [`CanonicalFinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiftError {
    /// The finding's byte span is empty or inverted, so it does not describe a
    /// region that could have been matched.
    MalformedSpan {
        /// The finding's start offset.
        offset: usize,
        /// The finding's end offset.
        end: usize,
    },
}

impl core::fmt::Display for LiftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedSpan { offset, end } => {
                write!(f, "finding span {offset}..{end} is empty or inverted")
            }
        }
    }
}

impl std::error::Error for LiftError {}

impl TryFrom<&CredentialFinding> for CanonicalFinding {
    type Error = LiftError;

    /// Describe a scanner finding in canonical terms.
    ///
    /// Every [`CredentialKind`] has a canonical category — that half is
    /// exhaustive — but the conversion as a whole is **fallible on purpose**,
    /// and the reason is not hypothetical.
    ///
    /// [`CredentialFinding`] derives `Deserialize` under the `serde` feature
    /// with `end` marked `#[serde(skip)]`, so a finding reconstructed from JSON
    /// arrives with `end == 0` regardless of its offset. That is a real path: it
    /// is one `serde_json::from_str` away in any crate that enables the same
    /// feature B-9's event layer needs for `Serialize`. An infallible `From`
    /// would turn such a value into a canonical finding carrying an inverted
    /// span, silently, while attributing it to the built-in scanner.
    ///
    /// So the span is checked rather than trusted. A finding covers at least one
    /// byte — every detector matches a non-empty literal, digit run, PEM header
    /// or token — and anything else is refused rather than repaired, because a
    /// span that cannot be believed must not become a finding that looks
    /// believable (ADR 0032 §5: never silently degrade).
    ///
    /// This is a **well-formedness** check, not a provenance one. It cannot tell
    /// a scanner-produced finding from a well-formed forgery, and nothing in
    /// this crate can — see [`Provenance`] for what identity does and does not
    /// guarantee.
    fn try_from(finding: &CredentialFinding) -> Result<Self, Self::Error> {
        let (offset, end) = (finding.offset, finding.end());
        if end <= offset {
            return Err(LiftError::MalformedSpan { offset, end });
        }
        let confidence = ConfidenceBand::for_credential_kind(&finding.kind);
        Ok(Self {
            category: CanonicalCategory::from_credential_kind(&finding.kind),
            severity: Severity::for_credential_kind(&finding.kind),
            confidence,
            span: ByteSpan::new(offset, end),
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CredentialScanner;

    /// The exact bypass this module's fallibility exists for.
    ///
    /// `CredentialFinding` derives `Deserialize` with `end` skipped, so a
    /// finding rebuilt from JSON has `end == 0`. Before the lift was fallible
    /// this produced a canonical finding with an inverted span and the built-in
    /// scanner's provenance, silently. Constructed here through the same public
    /// API a downstream crate has — `from_regex_match` leaves `end` at the
    /// caller's value — so the test fails if the check is ever removed.
    #[test]
    fn a_finding_with_an_empty_or_inverted_span_is_refused() {
        // `end == offset`: the shape a `#[serde(skip)]` round-trip produces when
        // the offset is 0, and the shape a zero-length match would have.
        let empty = CredentialFinding::from_regex_match(0, 0);
        assert_eq!(
            CanonicalFinding::try_from(&empty),
            Err(LiftError::MalformedSpan { offset: 0, end: 0 })
        );

        // `end < offset`: what a deserialized finding with a non-zero offset
        // looks like, because `end` defaults while `offset` survives the wire.
        let inverted = CredentialFinding::from_regex_match(6, 0);
        assert_eq!(
            CanonicalFinding::try_from(&inverted),
            Err(LiftError::MalformedSpan { offset: 6, end: 0 })
        );

        // And the honest half: a well-formed span is still accepted, so the
        // check cannot be satisfied by refusing everything.
        let ok = CredentialFinding::from_regex_match(6, 26);
        assert!(CanonicalFinding::try_from(&ok).is_ok());
    }

    /// The canonical span must reproduce the scanner's own byte range, not just
    /// its start offset.
    ///
    /// This is the only test that exercises the `end` accessor added to
    /// `scanner.rs`, which is the entire reason that file was touched. The
    /// integration test cannot do it: `end()` is `pub(crate)`, so ground truth
    /// is unreachable from outside the crate.
    #[test]
    fn the_canonical_span_reproduces_the_scanner_byte_range() {
        let scanner = CredentialScanner::new();
        let corpus = [
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxGZ1bGxvZmVudHJvcHlkYXRh\n-----END RSA PRIVATE KEY-----",
            "DATABASE_URL=postgres://svc:hunter2@db.internal:5432/app",
            "contact alice.smith@example.com for access",
            "card on file 4111111111111111 expires soon",
        ];
        let mut checked = 0usize;
        for text in corpus {
            for finding in &scanner.scan(text).findings {
                let canonical = CanonicalFinding::try_from(finding).expect("scanner spans are well formed");
                assert_eq!(canonical.span.start(), finding.offset, "start moved");
                assert_eq!(canonical.span.end(), finding.end(), "end moved");
                // A span that reproduces both bounds must also slice the text.
                assert!(text.is_char_boundary(canonical.span.start()));
                assert!(text.is_char_boundary(canonical.span.end()));
                assert!(!canonical.span.is_empty(), "a finding always covers bytes");
                checked += 1;
            }
        }
        assert!(
            checked >= 5,
            "corpus produced too few findings to prove anything: {checked}"
        );
    }
}
