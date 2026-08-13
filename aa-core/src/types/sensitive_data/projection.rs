//! The bounded label set a sensitive-data metric may carry.

use alloc::string::{String, ToString};

use aa_security::canonical::{CanonicalCategory, ConfidenceBand, DetectionMethod, Recognizer, Severity};

use super::finding_record::SensitiveDataFindingRecord;
use super::verdict::RuntimeVerdictLabel;
// `vocab` is referenced only from `cfg_attr(feature = "serde" / "schemars")`
// attributes on the fields below, so the import must carry the same condition
// or it is an `unused_imports` error whenever neither feature is on
// (AAASM-5682).
#[cfg(any(feature = "serde", feature = "schemars"))]
use super::vocab;

/// The six labels ADR 0032 §9 permits on a sensitive-data metric.
///
/// # Why this type exists rather than "just use the record"
///
/// AAASM-5352 left this ticket an explicit obligation. `CanonicalFinding`
/// derives `Serialize` and emits its [`ByteSpan`](aa_security::canonical::ByteSpan)
/// unconditionally, and `aa-security`'s `serde_impls.rs` records that the
/// resulting JSON is **audit-tier only**: ADR 0032 §9 permits offsets and
/// lengths solely in the tamper-evident tier, because a length plus a category
/// can identify a value in a small domain. A consumer that is not the audit
/// sink has to project a span-free subset rather than forward that output —
/// guarding the offset behind `pub(crate)` in Rust and then publishing it in
/// JSON to anything that asks would undo the guard one layer later.
///
/// [`SensitiveDataFindingRecord`] is already span-free. This narrows further,
/// to the exact set §9 allows on a metric:
///
/// > `{category, severity, confidence_band, outcome, detection_method, provider_id}`
///
/// # Bounded cardinality, by construction
///
/// ADR 0032 §9 bounds metric **series**, and a series is a name *and* a value.
/// Fixing the six names is only half of it; each value has to come from a
/// finite domain too.
///
/// So every field is drawn from a compile-time catalogue: five closed
/// `aa-security` vocabularies plus
/// [`CanonicalCategory::ALL`](aa_security::canonical::CanonicalCategory::ALL).
/// The category is held as a **resolved [`CanonicalCategory`]**, not as a
/// [`CategoryLabel`](super::CategoryLabel), and
/// [`from_finding`](Self::from_finding) returns `None` when the record's label
/// does not resolve. An unresolvable category is by definition not a member of
/// a bounded set, so it must not become a bounded label.
///
/// That refusal is the load-bearing part. A `CategoryLabel` is bounded in shape
/// and unbounded in value — it deliberately round-trips categories a newer
/// build produced — so rendering one straight into a metric would put an
/// arbitrary string in a series name. Worse, a `SensitiveDataFindingRecord`
/// deserialized from storage can carry any well-shaped label at all, which is
/// how a raw credential reached a metric label value in an earlier revision of
/// this type.
///
/// # What this does and does not guarantee
///
/// Stated as a property of the construction paths, not as a claim about the
/// type system, because the distinction has been got wrong here before.
///
/// **Guaranteed by construction:** the only way to build one of these is
/// [`from_finding`](Self::from_finding); the fields are private and the struct
/// is `#[non_exhaustive]`, so there is no struct literal and no post-hoc field
/// assignment; and every value it can hold is a member of a compile-time
/// catalogue. Validation requirement 4's forbidden labels — `agent_id`,
/// `destination`, `session_id`, and any fingerprint — have no way in.
///
/// **Not guaranteed:** this is `Serialize`-only and has no `Deserialize`, so
/// nothing reconstructs one from bytes; but a `ByteSpan` field added here would
/// still compile, because the absence of `Deserialize` is what makes a span a
/// type error over in [`SensitiveDataFindingRecord`](super::SensitiveDataFindingRecord).
/// Here only
/// [`the_metric_projection_serializes_only_the_six_permitted_labels`](#) stands
/// between an offset and a metric, and an assertion is something a future
/// change can delete.
///
/// # No tenant label, deliberately
///
/// ADR 0032 §9's permitted set does not include a tenant, and this type does not
/// add one. A tenant id is unbounded, and a metric series broken down by tenant
/// puts one tenant's activity in a series a shared dashboard can read.
///
/// The consequence is worth being clear about: **these metrics do not answer
/// per-tenant questions.** A tenant-scoped answer comes from querying the
/// events, which carry [`Tenancy`](super::Tenancy), and where the isolation can
/// actually be enforced by the query.
///
/// # Emitted, not stored
///
/// `Serialize` only. These labels go to a metrics exporter and are never read
/// back — the event is the record. Nothing here is a durable representation, so
/// nothing here needs to round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct SensitiveDataMetricLabels {
    /// The resolved category. Serialized through `rendered_category`.
    #[cfg_attr(feature = "serde", serde(skip))]
    category: CanonicalCategory,
    /// `category`'s rendering, derived from it at construction.
    ///
    /// Held rather than recomputed so [`as_pairs`](Self::as_pairs) can hand out
    /// a borrow without allocating on a metrics hot path. It cannot diverge
    /// from `category`: both are private, set together in the one constructor,
    /// and there is no `Deserialize` to reach around them.
    #[cfg_attr(feature = "serde", serde(rename = "category"))]
    rendered_category: String,
    #[cfg_attr(feature = "serde", serde(with = "vocab::severity"))]
    severity: Severity,
    #[cfg_attr(feature = "serde", serde(with = "vocab::confidence"))]
    confidence_band: ConfidenceBand,
    outcome: RuntimeVerdictLabel,
    #[cfg_attr(feature = "serde", serde(with = "vocab::method"))]
    detection_method: DetectionMethod,
    #[cfg_attr(feature = "serde", serde(with = "vocab::recognizer"))]
    provider_id: Recognizer,
}

impl SensitiveDataMetricLabels {
    /// The names of the six labels, in the order [`as_pairs`](Self::as_pairs)
    /// returns them.
    pub const LABEL_NAMES: [&'static str; 6] = [
        "category",
        "severity",
        "confidence_band",
        "outcome",
        "detection_method",
        "provider_id",
    ];

    /// Project a finding row and the action's verdict into metric labels.
    ///
    /// The only constructor. It takes a record and a verdict — never a string —
    /// so a caller cannot introduce a label value of its own.
    ///
    /// Returns `None` when the record's category does not resolve against this
    /// build's catalogue. That is not a failure to handle away: a category this
    /// build cannot name is not a bounded label, and emitting it would put an
    /// arbitrary string into a metric series. A caller should count the event
    /// under a separate "unresolvable category" series — a constant, and
    /// therefore bounded — rather than reach for the rendered form.
    pub fn from_finding(record: &SensitiveDataFindingRecord, outcome: RuntimeVerdictLabel) -> Option<Self> {
        let category = record.category.resolve()?;
        Some(Self {
            // Rendered from the *resolved* category, never from the record's
            // stored label, so the value is provably a member of the catalogue's
            // rendering set even when the record came from storage.
            rendered_category: category.to_string(),
            category,
            severity: record.severity,
            confidence_band: record.confidence,
            outcome,
            detection_method: record.method,
            provider_id: record.provenance.recognizer,
        })
    }

    /// The resolved category these labels describe.
    pub const fn category(&self) -> CanonicalCategory {
        self.category
    }

    /// How damaging exposure would be.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// How much the recognizer trusted the finding.
    pub const fn confidence_band(&self) -> ConfidenceBand {
        self.confidence_band
    }

    /// The enforcement outcome, as ADR 0018's frozen verdict label.
    pub const fn outcome(&self) -> RuntimeVerdictLabel {
        self.outcome
    }

    /// The technique that produced the finding.
    pub const fn detection_method(&self) -> DetectionMethod {
        self.detection_method
    }

    /// Which recognizer produced it. `provider_id` in §9's spelling.
    pub const fn provider_id(&self) -> Recognizer {
        self.provider_id
    }

    /// The labels as name/value pairs, ready for a metrics exporter.
    pub fn as_pairs(&self) -> [(&'static str, &str); 6] {
        [
            ("category", self.rendered_category.as_str()),
            ("severity", self.severity.as_str()),
            ("confidence_band", self.confidence_band.as_str()),
            ("outcome", self.outcome.as_str()),
            ("detection_method", self.detection_method.as_str()),
            ("provider_id", self.provider_id.as_str()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use aa_security::canonical::{CanonicalCategory, CategoryBase};

    use super::*;
    use crate::types::sensitive_data::event::fixtures::finding;

    fn labels() -> SensitiveDataMetricLabels {
        let record = finding(
            CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access"),
            "headers.authorization",
        );
        SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::DENY)
            .expect("a catalogue category resolves")
    }

    /// **ADR 0032 validation requirement 4.** The label names are exactly §9's
    /// six, and none of the forbidden dimensions is among them.
    ///
    /// Asserted as an equality against the full expected set rather than as a
    /// series of `assert!(!contains(...))` checks: a "does not contain
    /// agent_id" test keeps passing when someone adds `tool_name`, and the
    /// cardinality problem is the same one.
    #[test]
    fn the_label_names_are_exactly_the_six_the_adr_permits() {
        assert_eq!(
            SensitiveDataMetricLabels::LABEL_NAMES,
            [
                "category",
                "severity",
                "confidence_band",
                "outcome",
                "detection_method",
                "provider_id"
            ]
        );

        let emitted: alloc::vec::Vec<&str> = labels().as_pairs().iter().map(|(name, _)| *name).collect();
        assert_eq!(emitted, SensitiveDataMetricLabels::LABEL_NAMES.to_vec());

        for forbidden in [
            "agent_id",
            "destination",
            "session_id",
            "tenant_id",
            "field_path",
            "span",
            "fingerprint",
        ] {
            assert!(
                !emitted.contains(&forbidden),
                "`{forbidden}` reached a metric label; ADR 0032 §9 restricts labels to a bounded set"
            );
        }
    }

    /// Every label value comes from a compile-time catalogue, so the series
    /// count is finite. Demonstrated over the whole category catalogue, which is
    /// the only field with more than a handful of values.
    #[test]
    fn every_category_in_the_catalogue_produces_a_bounded_label() {
        for category in CanonicalCategory::ALL {
            let record = finding(*category, "body.field");
            let labels = SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::SCRUB)
                .expect("a catalogue category resolves");
            assert_eq!(
                labels.category(),
                *category,
                "a metric label escaped the catalogue it is supposed to be bounded by"
            );
        }
    }

    /// The values carry the documented spellings, not Rust identifiers.
    #[test]
    fn the_label_values_use_the_published_spellings() {
        let labels = labels();
        let pairs = labels.as_pairs();
        assert_eq!(pairs[0].1, "ACCESS_TOKEN[github:personal_access]");
        assert_eq!(pairs[1].1, "critical");
        assert_eq!(pairs[2].1, "high");
        assert_eq!(pairs[3].1, "deny");
        assert_eq!(pairs[4].1, "deterministic");
        assert_eq!(pairs[5].1, "aa-security::scanner");
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use aa_security::canonical::{CanonicalCategory, CategoryBase};

    use super::*;
    use crate::types::sensitive_data::event::fixtures::finding;

    /// **The span-free-subset test AAASM-5352 asked this ticket for.**
    ///
    /// The record it is projected from was built from a finding whose span is
    /// `4..44`, and neither the offsets nor the length may appear here.
    /// Asserted on the serialized JSON keys *and* values: a length can leak as
    /// a number under an innocent name just as easily as under `length`.
    #[test]
    fn the_metric_projection_serializes_only_the_six_permitted_labels() {
        let record = finding(
            CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access"),
            "headers.authorization",
        );
        let labels = SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::DENY)
            .expect("a catalogue category resolves");
        let json = serde_json::to_value(labels).unwrap();

        let object = json.as_object().expect("labels serialize as an object");
        let mut keys: alloc::vec::Vec<&str> = object.keys().map(alloc::string::String::as_str).collect();
        keys.sort_unstable();
        let mut expected = SensitiveDataMetricLabels::LABEL_NAMES.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected, "the metric projection changed shape");

        for (key, value) in object {
            assert!(
                value.is_string(),
                "label `{key}` serialized as {value}, and a non-string label is how an offset or a length gets out"
            );
        }
    }
}
