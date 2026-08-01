//! The canonical finding and the vocabularies it is built from.

use super::CanonicalCategory;

/// The byte region of the scanned input a finding covers.
///
/// Half-open: `start..end`, both byte offsets into the text that was scanned.
///
/// ADR 0032 §9 permits offsets and lengths **only** in the tamper-evident audit
/// tier, because a length plus a category can identify a value in a small
/// domain. A span must therefore never reach a metric label, a trace attribute
/// or an API response; the field *path* is the drill-down granularity those get.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct ByteSpan {
    start: usize,
    end: usize,
}

impl ByteSpan {
    /// Build a span from its byte bounds.
    ///
    /// Bounds are not validated against any text here — a span is only ever as
    /// good as the detection source that produced it, which is why
    /// [`ScanResult::redact`](crate::scanner::ScanResult::redact) fails closed
    /// on a span it cannot splice rather than trusting one.
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// First byte offset of the finding.
    pub const fn start(&self) -> usize {
        self.start
    }

    /// One past the last byte offset of the finding.
    pub const fn end(&self) -> usize {
        self.end
    }

    /// Length of the span in bytes, saturating if the bounds are inverted.
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How damaging the exposure of this category of value is.
///
/// The same four-level scale
/// [`CredentialKind::severity`](crate::scanner::CredentialKind::severity)
/// already publishes over `GET /api/v1/scrub/patterns`, lifted into a type so
/// the canonical model does not introduce a second, divergent scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Direct access to a live account, key or regulated identifier.
    Critical,
    /// Access that is meaningful but mediated, such as a connection URI.
    High,
    /// Personal data whose exposure is harmful but not access-granting.
    Medium,
    /// A weak signal that something might be sensitive.
    Low,
}

impl Severity {
    /// The published spelling of this level.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Parse the published spelling, or `None` if it is not one of the four.
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

/// How much the producing recognizer trusts the finding.
///
/// Deliberately a three-value band rather than a score, and deliberately **not**
/// ordered: `PartialOrd` is not derived so `confidence >= threshold` does not
/// compile. Confidence is evidence about a detection, never an authorisation
/// input — Agent Assembly owns the decision (ADR 0032 §4 carve-out, ADR 0002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfidenceBand {
    /// A recognizer that identified the exact thing it found.
    High,
    /// A recognizer with a real false-positive rate, such as a format match
    /// with no checksum.
    Medium,
    /// A backstop that flagged the shape of the data, not its identity.
    Low,
}

impl ConfidenceBand {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// The technique that produced a finding.
///
/// This is the dimension operators need in order to read a false-positive
/// report: a `deterministic` hit and a `heuristic` hit warrant very different
/// responses, and today both arrive labelled only with a `CredentialKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectionMethod {
    /// A literal, structural or checksum match that cannot be wrong about what
    /// it matched.
    Deterministic,
    /// A statistical or shape-based signal, such as the entropy backstop.
    Heuristic,
    /// A natural-language model. No v1 detection source uses this; the variant
    /// exists so the vocabulary does not have to change when reporting on a
    /// source that does.
    Nlp,
    /// An operator-authored pattern from the active policy document.
    PolicyDefined,
}

impl DetectionMethod {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Heuristic => "heuristic",
            Self::Nlp => "nlp",
            Self::PolicyDefined => "policy_defined",
        }
    }
}

/// The triage state of a finding.
///
/// Every value except [`FindingStatus::Dismissed`] still denotes a finding.
/// Nothing in this vocabulary means "clean": a detection source that could not
/// handle its input records a failure outcome elsewhere and never emits a
/// finding claiming the input was fine (ADR 0032 §5, validation requirement 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingStatus {
    /// The recognizer is certain of what it found.
    Confirmed,
    /// A real finding from a source that can be wrong about it.
    Suspected,
    /// Two sources described the same span incompatibly. Recorded rather than
    /// resolved by picking a winner, because "top-scoring entity wins" is an
    /// explicitly forbidden design (ADR 0032 forbidden design #5).
    ProviderDisagreement,
    /// Escalated for a human to look at.
    NeedsReview,
    /// Judged not to be sensitive after review. Retained rather than deleted so
    /// the dismissal is itself auditable.
    Dismissed,
}

impl FindingStatus {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Suspected => "suspected",
            Self::ProviderDisagreement => "provider_disagreement",
            Self::NeedsReview => "needs_review",
            Self::Dismissed => "dismissed",
        }
    }
}

/// A detection source that exists in this build.
///
/// A closed enum rather than a string, so a recognizer identity cannot be
/// invented at runtime. `&'static str` would not have achieved that: `Box::leak`
/// turns any runtime `String` into a `&'static str` in safe, stable Rust, so a
/// string-typed identity is a convention, not a boundary. Adding a recognizer —
/// B-7's locale packs are next — is a source change, which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Recognizer {
    /// The built-in Aho-Corasick scanner in [`crate::scanner`].
    BuiltinScanner,
}

impl Recognizer {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BuiltinScanner => "aa-security::scanner",
        }
    }
}

/// Which recognizer produced a finding, and at which version.
///
/// The identity is a [`Recognizer`], so it cannot be forged from runtime bytes.
/// The version is descriptive rather than a trust signal — it says which build's
/// detectors ran, not that they really did.
///
/// **This is not an authenticity boundary.** Provenance is stamped by whoever
/// constructs the finding; it records which recognizer a value *claims* to come
/// from. Nothing in this crate can distinguish a genuine scanner finding from a
/// well-formed forgery, and no v1 code path needs to — ADR 0032 validation
/// requirement 10 is about an out-of-process provider being unreachable from a
/// synchronous path, which is trivially satisfied here because no provider
/// exists (D-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Provenance {
    /// Which recognizer the finding claims to come from.
    pub recognizer: Recognizer,
    /// Version of that recognizer.
    pub version: &'static str,
}

impl Provenance {
    /// Name a recognizer and its version.
    pub const fn new(recognizer: Recognizer, version: &'static str) -> Self {
        Self { recognizer, version }
    }
}

/// One canonical, provider-neutral sensitive-data finding (ADR 0032 §2).
///
/// Note what this struct does *not* have: an owned `String`. Category and
/// provenance are `&'static str` behind their types, and the rest is enums and
/// offsets. A raw matched value is not merely forbidden here, it is
/// unrepresentable, which is the strongest form of the guarantee
/// [`CredentialFinding`](crate::scanner::CredentialFinding) makes by storing the
/// redaction label instead of the match (ADR 0032 §9, validation requirement 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct CanonicalFinding {
    /// What was found, in provider-neutral terms.
    pub category: CanonicalCategory,
    /// How damaging its exposure would be.
    pub severity: Severity,
    /// How much the recognizer trusts the finding. Never an authorisation input.
    pub confidence: ConfidenceBand,
    /// The byte region covered. Audit tier only — see [`ByteSpan`].
    pub span: ByteSpan,
    /// The technique that produced it.
    pub method: DetectionMethod,
    /// Which recognizer produced it, and at which version.
    pub provenance: Provenance,
    /// Its triage state.
    pub status: FindingStatus,
}
