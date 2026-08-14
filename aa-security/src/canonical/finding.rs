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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// An operator-authored `data.sensitive_patterns` regex, evaluated by the
    /// gateway's policy engine rather than by the built-in scanner.
    ///
    /// These findings reach the canonical model through
    /// [`CredentialFinding::from_regex_match`](crate::scanner::CredentialFinding::from_regex_match),
    /// which `aa-gateway` calls from `engine/mod.rs`. Attributing them to the
    /// built-in scanner would name a detector that never ran.
    PolicyRegex,
    /// The zh-TW deterministic locale pack in [`crate::locale::zh_tw`]
    /// (AAASM-5353).
    ///
    /// Its own identity rather than [`Recognizer::BuiltinScanner`], for the same
    /// reason [`Recognizer::PolicyRegex`] has one: it is a different detector,
    /// running from a different entry point, over a different alphabet, with a
    /// different residual false-positive profile. An operator reading a
    /// false-positive report needs to know a hit came from a checksum over
    /// Taiwanese identifiers and not from the Aho-Corasick literal scan, because
    /// the two warrant different responses — and because these findings carry no
    /// `CredentialKind`, the recognizer is the only axis that says so.
    ZhTwLocalePack,
}

impl Recognizer {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BuiltinScanner => "aa-security::scanner",
            Self::PolicyRegex => "aa-gateway::policy_regex",
            Self::ZhTwLocalePack => "aa-security::locale::zh_tw",
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
/// # Construction
///
/// Fields are private and there are exactly two ways in:
/// [`TryFrom<&CredentialFinding>`](CanonicalFinding#impl-TryFrom<%26CredentialFinding>)
/// and [`new`](Self::new). Both run the same span check.
///
/// That is deliberate rather than tidiness. With public fields a caller could
/// write the struct literal directly and reproduce exactly the state the
/// fallible lift exists to reject — an inverted span carrying the built-in
/// scanner's provenance — and could equally assign one after the fact. An
/// invariant enforced only on one construction path is not an invariant.
///
/// # What it cannot carry, and what it can
///
/// There is no owned `String` field: category and provenance hold
/// `&'static str`, and the rest is enums and offsets. So a finding built by
/// this crate carries no raw matched value — the lift derives category and
/// provenance from compiled-in constants only, never from scanned bytes, which
/// is the same guarantee [`CredentialFinding`](crate::scanner::CredentialFinding)
/// gives by storing the redaction label instead of the match (ADR 0032 §9,
/// validation requirement 9).
///
/// This is a property of **how this crate constructs findings**, not of the
/// types. `&'static str` does not mean "compiled in": `Box::leak` produces one
/// from arbitrary runtime bytes in safe stable Rust, so a caller determined to
/// put a secret in a qualifier or a version string can. See
/// [`CategoryQualifier`](crate::canonical::CategoryQualifier) for the same note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct CanonicalFinding {
    category: CanonicalCategory,
    severity: Severity,
    confidence: ConfidenceBand,
    span: ByteSpan,
    method: DetectionMethod,
    provenance: Provenance,
    status: FindingStatus,
}

impl CanonicalFinding {
    /// Assemble a finding, rejecting a span that is empty or inverted.
    ///
    /// The same check [`TryFrom<&CredentialFinding>`](CanonicalFinding) applies,
    /// so a hand-built finding cannot express a state a lifted one could not.
    ///
    /// # Errors
    ///
    /// [`LiftError::MalformedSpan`](crate::canonical::LiftError::MalformedSpan)
    /// when `span.end() <= span.start()`. A finding covers at least one byte.
    pub fn new(
        category: CanonicalCategory,
        severity: Severity,
        confidence: ConfidenceBand,
        span: ByteSpan,
        method: DetectionMethod,
        provenance: Provenance,
        status: FindingStatus,
    ) -> Result<Self, crate::canonical::LiftError> {
        if span.end() <= span.start() {
            return Err(crate::canonical::LiftError::MalformedSpan {
                offset: span.start(),
                end: span.end(),
            });
        }
        Ok(Self {
            category,
            severity,
            confidence,
            span,
            method,
            provenance,
            status,
        })
    }

    /// What was found, in provider-neutral terms.
    pub const fn category(&self) -> CanonicalCategory {
        self.category
    }

    /// How damaging its exposure would be.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// How much the recognizer trusts the finding. Never an authorisation input.
    pub const fn confidence(&self) -> ConfidenceBand {
        self.confidence
    }

    /// The byte region covered. Audit tier only — see [`ByteSpan`].
    pub const fn span(&self) -> ByteSpan {
        self.span
    }

    /// The technique that produced it.
    pub const fn method(&self) -> DetectionMethod {
        self.method
    }

    /// Which recognizer produced it, and at which version.
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }

    /// Its triage state.
    pub const fn status(&self) -> FindingStatus {
        self.status
    }

    /// The same finding with a different triage state.
    ///
    /// Status is the one field a later stage legitimately changes — a review
    /// dismisses a finding or escalates it — and it carries no invariant, so it
    /// moves through a transition rather than through a mutable field.
    #[must_use]
    pub const fn with_status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }
}
