//! The bounded label set a sensitive-data metric may carry.

use aa_security::canonical::{ConfidenceBand, DetectionMethod, Recognizer, Severity};

use super::finding_record::SensitiveDataFindingRecord;
use super::verdict::RuntimeVerdictLabel;
use super::vocab;
use super::CategoryLabel;

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
/// Every field is drawn from a compile-time catalogue: five closed
/// `aa-security` vocabularies plus [`CanonicalCategory::ALL`](aa_security::canonical::CanonicalCategory::ALL).
/// There is no constructor that takes a string. That is what keeps a metric
/// series count finite, and it is why validation requirement 4's forbidden
/// labels — `agent_id`, `destination`, `session_id`, and any fingerprint — are
/// not merely absent but unrepresentable here.
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
pub struct SensitiveDataMetricLabels {
    /// The finding's canonical category, rendered. Bounded by the catalogue.
    pub category: CategoryLabel,
    /// How damaging exposure would be.
    #[cfg_attr(feature = "serde", serde(with = "vocab::severity"))]
    pub severity: Severity,
    /// How much the recognizer trusted the finding.
    #[cfg_attr(feature = "serde", serde(with = "vocab::confidence"))]
    pub confidence_band: ConfidenceBand,
    /// The enforcement outcome, as ADR 0018's frozen verdict label.
    pub outcome: RuntimeVerdictLabel,
    /// The technique that produced the finding.
    #[cfg_attr(feature = "serde", serde(with = "vocab::method"))]
    pub detection_method: DetectionMethod,
    /// Which recognizer produced it. `provider_id` in §9's spelling.
    #[cfg_attr(feature = "serde", serde(with = "vocab::recognizer"))]
    pub provider_id: Recognizer,
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
    /// so a caller cannot introduce a label of its own, which is what makes the
    /// cardinality argument hold rather than merely be intended.
    pub fn from_finding(record: &SensitiveDataFindingRecord, outcome: RuntimeVerdictLabel) -> Self {
        Self {
            category: record.category.clone(),
            severity: record.severity,
            confidence_band: record.confidence,
            outcome,
            detection_method: record.method,
            provider_id: record.provenance.recognizer,
        }
    }

    /// The labels as name/value pairs, ready for a metrics exporter.
    pub fn as_pairs(&self) -> [(&'static str, &str); 6] {
        [
            ("category", self.category.as_str()),
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
            let labels = SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::SCRUB);
            assert_eq!(
                labels.category.resolve(),
                Some(*category),
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
        let json = serde_json::to_value(SensitiveDataMetricLabels::from_finding(
            &record,
            RuntimeVerdictLabel::DENY,
        ))
        .unwrap();

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
