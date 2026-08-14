//! The finding-level child row of a sensitive-data decision event.

use alloc::string::String;

use aa_security::canonical::{
    CanonicalFinding, ConfidenceBand, DetectionMethod, FindingStatus, Provenance, Recognizer, Severity,
};

use super::guard::{AuditLabel, FieldPath, FieldRejection};
use super::schema::{SchemaVersion, SENSITIVE_DATA_SCHEMA_VERSION};
// `vocab` is referenced only from `cfg_attr(feature = "serde" / "schemars")`
// attributes on the fields below, so the import must carry the same condition
// or it is an `unused_imports` error whenever neither feature is on
// (AAASM-5682).
#[cfg(any(feature = "serde", feature = "schemars"))]
use super::vocab;
use super::CategoryLabel;

/// Which recognizer produced a finding, and at which version.
///
/// The `aa-core` counterpart of
/// [`Provenance`](aa_security::canonical::Provenance), which cannot be stored
/// directly because its `version` is a `&'static str` and nothing deserializes
/// into one.
///
/// Carries the same warning `aa-security` attaches to its own type, because
/// nothing about crossing into a record improves it: **this is not an
/// authenticity boundary.** Provenance is stamped by whoever built the finding.
/// It records which recognizer a value *claims* to come from, and a well-formed
/// forgery is indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct DetectionProvenance {
    /// The detection source the finding claims to come from.
    #[cfg_attr(feature = "serde", serde(with = "vocab::recognizer"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::recognizer::schema"))]
    pub recognizer: Recognizer,
    /// Version of that recognizer. Descriptive, not a trust signal — it says
    /// which build's detectors ran, not that they really did.
    pub version: AuditLabel,
}

impl DetectionProvenance {
    /// Name a recognizer and its version.
    ///
    /// # Errors
    ///
    /// Whatever [`AuditLabel::new`] rejects the version for.
    pub fn new(recognizer: Recognizer, version: impl Into<String>) -> Result<Self, FieldRejection> {
        Ok(Self {
            recognizer,
            version: AuditLabel::new(version)?,
        })
    }
}

impl TryFrom<Provenance> for DetectionProvenance {
    type Error = FieldRejection;

    /// Fallible only because the version is re-checked on the way in.
    ///
    /// In practice `aa-security` builds it from `CARGO_PKG_VERSION`, so this
    /// does not fail — but the check is not skipped on that basis, because
    /// `&'static str` does not mean "compiled in" (`Box::leak` produces one
    /// from arbitrary runtime bytes in safe Rust), and this crate would rather
    /// not have an unchecked way in.
    fn try_from(provenance: Provenance) -> Result<Self, Self::Error> {
        Self::new(provenance.recognizer, provenance.version)
    }
}

/// The stable identity a finding is grouped and deduplicated by.
///
/// # Not a fingerprint
///
/// ADR 0032 §9 permits tenant-keyed HMAC fingerprints only above roughly 80 bits
/// of value entropy, which excludes every PII category: a Taiwan national ID has
/// about 5.2 × 10⁸ candidates and enumerates in well under a second on one GPU
/// given the tenant key. Forbidden design #14 names it directly.
///
/// So this key is built from **where and what**, never from the value: the
/// category, the field path, the detection method and the recognizer. Two
/// different national IDs found in the same field under the same category
/// produce the *same* key. That is the intended behaviour for deduplication,
/// and it is also precisely why the key is safe — it cannot distinguish one
/// value from another, so it cannot be enumerated back to one.
///
/// # Not a metric label
///
/// The key embeds a field path, which is caller-derived and unbounded.
/// ADR 0032 §9 restricts metric labels to a bounded set; use
/// [`SensitiveDataMetricLabels`](super::SensitiveDataMetricLabels) for that.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct AggregateKey(String);

impl AggregateKey {
    /// The key as a single string, `category|field_path|method|recognizer`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for AggregateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One normalized finding, as it appears beneath a
/// [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent).
///
/// # Span-free by construction
///
/// A [`CanonicalFinding`] carries a [`ByteSpan`](aa_security::canonical::ByteSpan),
/// and ADR 0032 §9 permits offsets and lengths **only** in the tamper-evident
/// audit tier — a length plus a category can identify a value in a small domain,
/// and forbidden design #12 puts them out of bounds for metric labels, traces
/// and API responses outright.
///
/// This record is the other tier. [`from_finding`](Self::from_finding) reads a
/// canonical finding and **discards** the span; there is no field to put one in
/// and no accessor to get one out. AAASM-5352 recorded this obligation against
/// this ticket in `aa-security`'s `serde_impls.rs`, observing that it would be
/// incoherent to keep `end()` `pub(crate)` in Rust and then publish the offset
/// in JSON to anything that asks. Discharged here.
///
/// # What it can carry
///
/// Three of its fields hold caller-supplied strings, at three strengths, and
/// it is worth being exact about which is which:
///
/// | Field | Guard on the way in |
/// |---|---|
/// | [`field_path`](Self::field_path) | credential scan **and** shape check |
/// | [`event_id`](Self::event_id), [`provenance.version`](DetectionProvenance::version) | shape check only ([`AuditLabel`]) |
/// | [`category`](Self::category), [`redaction_label`](Self::redaction_label) | shape check only; *derived* by [`from_finding`](Self::from_finding), but see below |
///
/// [`from_finding`](Self::from_finding) derives the category and the redaction
/// label from the finding and offers no parameter for either, so **that path**
/// cannot be handed arbitrary text. Everything else it writes comes from
/// `aa-security`'s compiled-in vocabularies.
///
/// # What that does not mean
///
/// The same honesty `aa-security` applies to its own model applies here: this
/// is a property of the construction paths, **not an unrepresentable state**.
/// Two ways around it, both deliberate:
///
/// - the fields are `pub`, so a caller can assign one after construction; and
/// - `Deserialize` rebuilds a record from bytes, re-checking shape but never
///   re-screening, because a stored record has to round-trip even if a later
///   build tightens the rules.
///
/// So a record in hand is **not** evidence that its category is one this build
/// knows or that its labels are bounded. A consumer that needs either must
/// check — which is exactly why
/// [`SensitiveDataMetricLabels::from_finding`](super::SensitiveDataMetricLabels::from_finding)
/// resolves the category and returns `None` rather than trusting this type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct SensitiveDataFindingRecord {
    /// Schema this row was written against.
    pub schema_version: SchemaVersion,
    /// The [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent)
    /// this finding belongs to.
    ///
    /// Without it "child row" would be a name rather than a relationship: the
    /// event holds no `Vec<SensitiveDataFindingRecord>` — [`FindingCounts::tally`](super::FindingCounts::tally)
    /// consumes the rows and keeps only the tallies — so this is the *only*
    /// thing tying a finding to the action it came from. Aggregating without it
    /// leaves `finding_counts.by_category` as the sole answer to the Epic's
    /// motivating question, which drops severity, confidence, method, status,
    /// field path and provenance.
    pub event_id: AuditLabel,
    /// What was found, in provider-neutral terms.
    pub category: CategoryLabel,
    /// How damaging its exposure would be.
    #[cfg_attr(feature = "serde", serde(with = "vocab::severity"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::severity::schema"))]
    pub severity: Severity,
    /// How much the recognizer trusts the finding. Never an authorisation input.
    #[cfg_attr(feature = "serde", serde(with = "vocab::confidence"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::confidence::schema"))]
    pub confidence: ConfidenceBand,
    /// The technique that produced it.
    #[cfg_attr(feature = "serde", serde(with = "vocab::method"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::method::schema"))]
    pub method: DetectionMethod,
    /// Its triage state. Nothing in this vocabulary means "clean".
    #[cfg_attr(feature = "serde", serde(with = "vocab::status"))]
    #[cfg_attr(feature = "schemars", schemars(schema_with = "vocab::status::schema"))]
    pub status: FindingStatus,
    /// Which recognizer claims to have produced it, and at which version.
    pub provenance: DetectionProvenance,
    /// The name of the inspected field. The drill-down granularity ADR 0032 §9
    /// grants in place of the byte offsets this tier may not have.
    pub field_path: FieldPath,
    /// The `[REDACTED:…]` label this finding redacts to.
    ///
    /// Stored rather than recomputed on read: it is what the writing build
    /// actually emitted, and for a category a reader does not know, the
    /// writer's label is the more accurate of the two.
    pub redaction_label: AuditLabel,
}

impl SensitiveDataFindingRecord {
    /// Project a canonical finding into a storable row, dropping the span.
    ///
    /// `event_id` is required rather than optional: a finding row that cannot
    /// name its parent event is not a child row.
    ///
    /// The redaction label is derived from the finding's category — there is no
    /// parameter for it, so a caller cannot substitute text of its own.
    ///
    /// # Errors
    ///
    /// [`FieldRejection`] if the derived redaction label or the recognizer
    /// version fails the shape check. The `field_path` was screened when it was
    /// built.
    pub fn from_finding(
        event_id: AuditLabel,
        finding: &CanonicalFinding,
        field_path: FieldPath,
    ) -> Result<Self, FieldRejection> {
        let category = finding.category();
        Ok(Self {
            schema_version: SENSITIVE_DATA_SCHEMA_VERSION,
            event_id,
            category: CategoryLabel::from(category),
            severity: finding.severity(),
            confidence: finding.confidence(),
            method: finding.method(),
            status: finding.status(),
            provenance: DetectionProvenance::try_from(finding.provenance())?,
            field_path,
            redaction_label: AuditLabel::new(category.redaction_label())?,
        })
    }

    /// The identity this row deduplicates and aggregates under.
    ///
    /// Derived on demand rather than stored. A stored copy is a second source of
    /// truth for something already fully determined by the row, and the failure
    /// mode of that is a key that disagrees with the record it keys.
    pub fn aggregate_key(&self) -> AggregateKey {
        AggregateKey(alloc::format!(
            "{}|{}|{}|{}",
            self.category,
            self.field_path,
            self.method.as_str(),
            self.provenance.recognizer.as_str()
        ))
    }
}

#[cfg(test)]
mod tests {
    use aa_security::canonical::{ByteSpan, CanonicalCategory, CategoryBase};
    use aa_security::CredentialScanner;

    use super::*;

    /// Build a finding without going near a real secret.
    fn synthetic_finding(category: CanonicalCategory, severity: Severity) -> CanonicalFinding {
        CanonicalFinding::new(
            category,
            severity,
            ConfidenceBand::High,
            ByteSpan::new(12, 52),
            DetectionMethod::Deterministic,
            Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
            FindingStatus::Confirmed,
        )
        .expect("well-formed span")
    }

    fn a_record() -> SensitiveDataFindingRecord {
        SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(
                CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access"),
                Severity::Critical,
            ),
            FieldPath::parse("body.headers.authorization").unwrap(),
        )
        .unwrap()
    }

    /// The record faithfully carries everything the finding said.
    #[test]
    fn a_record_carries_the_findings_classification() {
        let record = a_record();
        assert_eq!(record.category.as_str(), "ACCESS_TOKEN[github:personal_access]");
        assert_eq!(record.severity, Severity::Critical);
        assert_eq!(record.confidence, ConfidenceBand::High);
        assert_eq!(record.method, DetectionMethod::Deterministic);
        assert_eq!(record.status, FindingStatus::Confirmed);
        assert_eq!(record.provenance.recognizer, Recognizer::BuiltinScanner);
        assert_eq!(record.provenance.version.as_str(), "0.0.0-test");
        assert_eq!(record.schema_version, SENSITIVE_DATA_SCHEMA_VERSION);
    }

    /// The redaction label reproduces the published `CredentialKind` label for a
    /// category that maps back to one — the frozen contract
    /// `GET /api/v1/scrub/patterns` serves.
    #[test]
    fn the_redaction_label_is_derived_from_the_category() {
        assert_eq!(a_record().redaction_label.as_str(), "[REDACTED:GitHubPat]");
    }

    /// A category with no `CredentialKind` gets the opaque sentinel, not an
    /// invented `[REDACTED:<category>]` — which would publish a pattern name
    /// that `/api/v1/scrub/patterns` does not list and extend the frozen
    /// catalogue by accident.
    #[test]
    fn an_unmappable_category_redacts_to_the_opaque_label() {
        let record = SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(
                CanonicalCategory::with_locale(CategoryBase::NationalId, "xx-ZZ", "synthetic_for_test"),
                Severity::Medium,
            ),
            FieldPath::parse("body.id").unwrap(),
        )
        .unwrap();
        assert_eq!(record.redaction_label.as_str(), "[REDACTED]");
    }

    /// Findings of the same category in the same field share a key, whatever
    /// the underlying values were. That is the deduplication behaviour, and it
    /// is the reason the key cannot be enumerated back to a value.
    #[test]
    fn the_aggregate_key_is_structural_and_not_value_derived() {
        let scanner = CredentialScanner::new();
        // Two different synthetic GitHub PATs.
        let first = scanner.scan("token ghp_16C7e42F292c6912E7710c838347Ae178B4a");
        let second = scanner.scan("token ghp_ZZZ7e42F292c6912E7710c838347Ae178B4a");
        let path = FieldPath::parse("body.token").unwrap();

        let key_of = |result: &aa_security::ScanResult| {
            let finding = CanonicalFinding::try_from(&result.findings[0]).unwrap();
            SensitiveDataFindingRecord::from_finding(
                AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
                &finding,
                path.clone(),
            )
            .unwrap()
            .aggregate_key()
        };

        assert_eq!(
            key_of(&first),
            key_of(&second),
            "two different values in the same field must aggregate together"
        );
    }

    /// The key still separates the dimensions it is supposed to. Without this,
    /// the previous test would be satisfied by a constant.
    #[test]
    fn the_aggregate_key_separates_field_and_category() {
        let base = a_record();
        let other_field = SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(
                CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access"),
                Severity::Critical,
            ),
            FieldPath::parse("body.other_field").unwrap(),
        )
        .unwrap();
        let other_category = SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(
                CanonicalCategory::unqualified(CategoryBase::EmailAddress),
                Severity::Medium,
            ),
            FieldPath::parse("body.headers.authorization").unwrap(),
        )
        .unwrap();

        assert_ne!(base.aggregate_key(), other_field.aggregate_key());
        assert_ne!(base.aggregate_key(), other_category.aggregate_key());
    }

    /// Severity is not part of the aggregate identity: it is a property of the
    /// category, so including it would add nothing and would split a group the
    /// moment a severity was retuned.
    #[test]
    fn the_aggregate_key_ignores_severity() {
        let path = FieldPath::parse("body.token").unwrap();
        let category = CanonicalCategory::unqualified(CategoryBase::EmailAddress);
        let critical = SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(category, Severity::Critical),
            path.clone(),
        )
        .unwrap();
        let low = SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &synthetic_finding(category, Severity::Low),
            path,
        )
        .unwrap();
        assert_eq!(critical.aggregate_key(), low.aggregate_key());
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use aa_security::canonical::{ByteSpan, CanonicalCategory, CategoryBase};

    use super::*;

    fn a_record() -> SensitiveDataFindingRecord {
        let finding = CanonicalFinding::new(
            CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access"),
            Severity::Critical,
            ConfidenceBand::High,
            ByteSpan::new(12, 52),
            DetectionMethod::Deterministic,
            Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
            FindingStatus::Confirmed,
        )
        .unwrap();
        SensitiveDataFindingRecord::from_finding(
            AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").unwrap(),
            &finding,
            FieldPath::parse("body.headers.authorization").unwrap(),
        )
        .unwrap()
    }

    /// **The span-free-subset test.** ADR 0032 §9 confines offsets and lengths
    /// to the tamper-evident audit tier, and this record is not that tier.
    ///
    /// Asserted against the serialized JSON rather than the struct definition,
    /// because the struct having no span field is only half of it — a nested
    /// type could reintroduce one, and the JSON is what actually leaves.
    #[test]
    fn a_serialized_record_carries_no_span_offset_or_length() {
        let json = serde_json::to_value(a_record()).unwrap();

        fn walk(value: &serde_json::Value, forbidden: &[&str]) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        assert!(
                            !forbidden.contains(&key.as_str()),
                            "the projection leaked `{key}`, which ADR 0032 §9 confines to the audit tier"
                        );
                        walk(child, forbidden);
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, forbidden)),
                _ => {}
            }
        }

        walk(&json, &["span", "start", "end", "offset", "length", "len"]);
    }

    /// The wire shape, pinned. Everything a consumer keys off is here, spelled
    /// the way `aa-security` spells it — `"critical"`, not `"Critical"`, and the
    /// rendered category rather than a nested object.
    #[test]
    fn a_finding_record_serializes_to_its_documented_shape() {
        assert_eq!(
            serde_json::to_string(&a_record()).unwrap(),
            concat!(
                r#"{"schema_version":{"major":1,"minor":0},"#,
                r#""event_id":"01HZX9V8ABCDEFGHJKMNPQRSTV","#,
                r#""category":"ACCESS_TOKEN[github:personal_access]","severity":"critical","#,
                r#""confidence":"high","method":"deterministic","status":"confirmed","#,
                r#""provenance":{"recognizer":"aa-security::scanner","version":"0.0.0-test"},"#,
                r#""field_path":"body.headers.authorization","redaction_label":"[REDACTED:GitHubPat]"}"#
            )
        );
    }

    #[test]
    fn a_finding_record_round_trips() {
        let record = a_record();
        let json = serde_json::to_string(&record).unwrap();
        let restored: SensitiveDataFindingRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, record);
        assert_eq!(restored.aggregate_key(), record.aggregate_key());
    }

    /// An unknown severity is refused rather than coerced. Reading
    /// `"catastrophic"` as `low` because it is first in some list would
    /// understate a finding forever.
    #[test]
    fn an_unknown_vocabulary_label_fails_to_deserialize() {
        let json = serde_json::to_string(&a_record())
            .unwrap()
            .replace(r#""severity":"critical""#, r#""severity":"catastrophic""#);
        assert!(serde_json::from_str::<SensitiveDataFindingRecord>(&json).is_err());
    }
}
