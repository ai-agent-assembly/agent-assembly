//! `Serialize` for the canonical model, written by hand rather than derived.
//!
//! Every vocabulary type in this module documents an `as_str()` as "the stable
//! spelling used in events and metric labels", and [`CanonicalCategory`]
//! documents its rendered `BASE[qualifier]` form as a contract. A derived
//! `Serialize` emits neither: it emits the Rust identifier (`"Critical"`,
//! `"PolicyDefined"`) and, for the category, a nested object
//! (`{"base":"AccessToken","qualifier":{"Scheme":{…}}}`). Shipping that would
//! have handed B-9's event layer a wire format contradicting the documented one,
//! which is the sort of shape mistake that propagates rather than gets caught.
//!
//! `#[serde(rename_all = …)]` would fix the enums but not the category, and it
//! would leave two places to keep in step. These impls delegate to the same
//! `as_str()` and `Display` the documentation names, so the JSON cannot drift
//! from the contract without the contract itself changing.
//!
//! There is deliberately **no `Deserialize`**. See the module documentation for
//! why nothing here reconstructs a finding from bytes.
//!
//! # Tier
//!
//! **This serialization is audit-tier only.** [`CanonicalFinding`]'s derived
//! `Serialize` emits its [`ByteSpan`](super::ByteSpan) unconditionally, and ADR
//! 0032 §9 permits offsets and lengths *only* in the tamper-evident audit tier —
//! a length plus a category can identify a value in a small domain. Forbidden
//! design #12 puts offsets out of bounds for metric labels, traces and API
//! responses outright.
//!
//! So a consumer that is not the audit sink must **project a span-free subset**
//! rather than forward this output. That obligation lands on AAASM-5355's event
//! and metric paths; it is recorded here because the shape is defined here, and
//! because `scanner.rs` keeps its `end()` accessor `pub(crate)` for the same
//! reason — it would be incoherent to guard the offset in Rust and then publish
//! it in JSON to anything that asks.

use serde::{Serialize, Serializer};

use super::{
    CanonicalCategory, CategoryBase, CategoryQualifier, ConfidenceBand, DetectionMethod, FindingStatus, Recognizer,
    Severity,
};

/// Serialize a type as whatever its `as_str()` returns.
macro_rules! serialize_as_str {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.serialize_str(self.as_str())
                }
            }
        )*
    };
}

serialize_as_str!(
    CategoryBase,
    Severity,
    ConfidenceBand,
    DetectionMethod,
    FindingStatus,
    Recognizer,
);

/// Serialize a type as its `Display` rendering.
macro_rules! serialize_as_display {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.collect_str(self)
                }
            }
        )*
    };
}

serialize_as_display!(CanonicalCategory, CategoryQualifier);

#[cfg(test)]
mod tests {
    use crate::canonical::CanonicalFinding;
    use crate::CredentialScanner;

    /// The serialized form of a complete finding, pinned.
    ///
    /// Nothing asserted the wire shape before, which is how a derived
    /// `Serialize` emitting `"Critical"` and a nested category object shipped
    /// while the documentation promised `"critical"` and
    /// `ACCESS_TOKEN[github:personal_access]`.
    ///
    /// **This golden is the audit-tier shape, not "the format B-9 reads".** It
    /// carries `span`, and ADR 0032 §9 confines offsets to the tamper-evident
    /// audit tier; B-9's metric and projection paths must emit a span-free
    /// subset. Pinning it here fixes the vocabulary — the spelling of every
    /// category, severity, method and status — which is the part every tier
    /// shares.
    #[test]
    fn a_canonical_finding_serializes_to_its_documented_spelling() {
        let scanner = CredentialScanner::new();
        let result = scanner.scan("token ghp_16C7e42F292c6912E7710c838347Ae178B4a");
        let finding = CanonicalFinding::try_from(&result.findings[0]).expect("well-formed span");

        let expected = format!(
            concat!(
                r#"{{"category":"ACCESS_TOKEN[github:personal_access]","severity":"critical","#,
                r#""confidence":"high","span":{{"start":6,"end":46}},"method":"deterministic","#,
                r#""provenance":{{"recognizer":"aa-security::scanner","version":"{}"}},"#,
                r#""status":"confirmed"}}"#
            ),
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(serde_json::to_string(&finding).unwrap(), expected);
    }

    /// Each vocabulary serializes to exactly what its `as_str()` returns, so the
    /// two cannot drift apart one variant at a time.
    #[test]
    fn every_vocabulary_value_serializes_as_its_as_str() {
        use crate::canonical::{ConfidenceBand, DetectionMethod, FindingStatus, Recognizer, Severity};

        macro_rules! assert_as_str {
            ($($value:expr),* $(,)?) => {
                $(
                    assert_eq!(
                        serde_json::to_string(&$value).unwrap(),
                        format!("\"{}\"", $value.as_str()),
                        "serialized form diverged from as_str() for {:?}",
                        $value
                    );
                )*
            };
        }

        assert_as_str!(
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            ConfidenceBand::High,
            ConfidenceBand::Medium,
            ConfidenceBand::Low,
            DetectionMethod::Deterministic,
            DetectionMethod::Heuristic,
            DetectionMethod::Nlp,
            DetectionMethod::PolicyDefined,
            FindingStatus::Confirmed,
            FindingStatus::Suspected,
            FindingStatus::ProviderDisagreement,
            FindingStatus::NeedsReview,
            FindingStatus::Dismissed,
            Recognizer::BuiltinScanner,
        );
    }

    /// A category serializes as the same string `Display` renders, for all 28.
    #[test]
    fn every_category_serializes_as_its_rendered_form() {
        use crate::canonical::CanonicalCategory;
        use crate::CredentialKind;

        for kind in CredentialKind::ALL
            .iter()
            .cloned()
            .chain(std::iter::once(CredentialKind::Custom))
        {
            let category = CanonicalCategory::from_credential_kind(&kind);
            assert_eq!(
                serde_json::to_string(&category).unwrap(),
                format!("\"{category}\""),
                "serialized category diverged from its rendered form for {}",
                kind.as_str()
            );
        }
    }
}
