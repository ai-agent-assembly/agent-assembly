//! Reading `aa-security`'s canonical vocabularies back out of a stored record.
//!
//! # Why this module has to exist
//!
//! `aa-security`'s canonical model implements `Serialize` and, deliberately, no
//! `Deserialize` at all: a finding is never reconstructed from bytes, only
//! derived from something the process detected. That is the right rule for a
//! *finding*, and it is the reason `aa-core` cannot simply derive
//! `Deserialize` on a record that embeds
//! [`Severity`](aa_security::canonical::Severity) and its siblings — and cannot
//! supply the missing impl either, because both the type and the trait are
//! foreign to this crate.
//!
//! `serde(with = …)` needs no trait impl, so each vocabulary gets a pair of free
//! functions here. Serialization delegates to `aa-security`'s own hand-written
//! impl, so the spelling cannot drift from the one AAASM-5352 pinned;
//! deserialization resolves against a list of variants and compares
//! `as_str()`, so it cannot drift either.
//!
//! # Fail-closed here, survives-unknown elsewhere
//!
//! An unrecognised label is a **hard deserialization error** for every
//! vocabulary in this module. That is the opposite of what
//! [`CategoryLabel`](super::CategoryLabel) does with an unknown category, and
//! the difference is deliberate:
//!
//! - The **category taxonomy is designed to grow** — ADR 0032 §2 exists so that
//!   a new locale pack is a new qualifier under an existing base, and
//!   `aa-security` documents the locale packs as the next addition. Categories
//!   will routinely be read by builds that predate them, so a record naming one
//!   must survive intact.
//! - These vocabularies are not. Severity is the same four-level scale already
//!   published over `GET /api/v1/scrub/patterns`; confidence is a three-value
//!   band that is deliberately not even ordered; a new [`Recognizer`] means a
//!   genuinely new detection source, not a new pattern — the locale packs
//!   extend the *built-in scanner*, which is already one of the two. A new value
//!   in any of them is a rare, deliberate contract change, and reading it as
//!   something else would be a guess about how severe a finding was or about
//!   which detector claimed it.
//!
//! The cost is real and worth stating: if `aa-security` does add a variant to
//! one of these `#[non_exhaustive]` enums, the list below stops being complete
//! and an older reader refuses a newer record outright. Refusing is the safe
//! direction — the alternative is inventing a severity — but the list is the
//! thing to update, which is what the size test exists to say.

use aa_security::canonical::{ConfidenceBand, DetectionMethod, FindingStatus, Recognizer, Severity};

/// Define the serde/schemars bridge for one `aa-security` vocabulary.
///
/// The variant list is the single source for deserialization *and* for the JSON
/// schema, and both read spellings through `as_str()`, so neither can disagree
/// with `aa-security`'s serialization.
macro_rules! vocabulary_bridge {
    ($module:ident, $ty:ty, [$($variant:expr),* $(,)?]) => {
        pub(super) mod $module {
            #[allow(unused_imports)]
            use super::*;

            /// Every variant of this vocabulary known to this build.
            pub(in crate::types::sensitive_data) const ALL: &[$ty] = &[$($variant),*];

            /// Resolve a wire label, or `None` if this build does not know it.
            pub(in crate::types::sensitive_data) fn from_label(label: &str) -> Option<$ty> {
                ALL.iter().copied().find(|value| value.as_str() == label)
            }

            #[cfg(feature = "serde")]
            pub fn serialize<S: serde::Serializer>(value: &$ty, serializer: S) -> Result<S::Ok, S::Error> {
                // Delegates to aa-security's hand-written impl rather than
                // re-emitting as_str(), so there is exactly one spelling.
                serde::Serialize::serialize(value, serializer)
            }

            #[cfg(feature = "serde")]
            pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<$ty, D::Error> {
                use serde::de::Error as _;
                use serde::Deserialize as _;
                let label = alloc::string::String::deserialize(deserializer)?;
                from_label(&label).ok_or_else(|| {
                    // The label is echoed because these vocabularies are closed
                    // and contain no caller data — there is nothing sensitive a
                    // severity label can hold.
                    D::Error::custom(alloc::format!(
                        "not a {} this build knows: {label:?}",
                        stringify!($ty)
                    ))
                })
            }

            #[cfg(feature = "schemars")]
            pub fn schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
                let variants: alloc::vec::Vec<&'static str> = ALL.iter().map(|value| value.as_str()).collect();
                schemars::json_schema!({
                    "type": "string",
                    "enum": variants,
                })
            }
        }
    };
}

vocabulary_bridge!(
    severity,
    Severity,
    [Severity::Critical, Severity::High, Severity::Medium, Severity::Low]
);

vocabulary_bridge!(
    confidence,
    ConfidenceBand,
    [ConfidenceBand::High, ConfidenceBand::Medium, ConfidenceBand::Low]
);

vocabulary_bridge!(
    method,
    DetectionMethod,
    [
        DetectionMethod::Deterministic,
        DetectionMethod::Heuristic,
        DetectionMethod::Nlp,
        DetectionMethod::PolicyDefined,
    ]
);

vocabulary_bridge!(
    status,
    FindingStatus,
    [
        FindingStatus::Confirmed,
        FindingStatus::Suspected,
        FindingStatus::ProviderDisagreement,
        FindingStatus::NeedsReview,
        FindingStatus::Dismissed,
    ]
);

vocabulary_bridge!(
    recognizer,
    Recognizer,
    [Recognizer::BuiltinScanner, Recognizer::PolicyRegex]
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every listed variant resolves from its own `as_str()`.
    ///
    /// Cheap, but it is what stops a hand-written list from containing a value
    /// whose spelling was typed rather than read — the failure mode a plain
    /// string match would have.
    #[test]
    fn every_listed_variant_resolves_from_its_own_spelling() {
        macro_rules! assert_resolves {
            ($($module:ident),* $(,)?) => {
                $(
                    assert!(!$module::ALL.is_empty(), "an empty list would make this vacuous");
                    for value in $module::ALL {
                        assert_eq!(
                            $module::from_label(value.as_str()),
                            Some(*value),
                            "{value:?} did not resolve from its own as_str()"
                        );
                    }
                )*
            };
        }
        assert_resolves!(severity, confidence, method, status, recognizer);
    }

    /// The counts these lists are believed complete at.
    ///
    /// Every one of these enums is `#[non_exhaustive]`, so the compiler will not
    /// notice a new variant — nothing here can be exhaustiveness-checked. A
    /// count is the crudest possible guard and it is the only one available:
    /// when `aa-security` adds a variant, this fails and points at the list that
    /// needs extending, instead of an older reader silently refusing newer
    /// records in production.
    #[test]
    fn the_vocabulary_lists_are_the_expected_size() {
        assert_eq!(severity::ALL.len(), 4, "aa-security's Severity scale changed size");
        assert_eq!(confidence::ALL.len(), 3, "aa-security's ConfidenceBand changed size");
        assert_eq!(method::ALL.len(), 4, "aa-security's DetectionMethod changed size");
        assert_eq!(status::ALL.len(), 5, "aa-security's FindingStatus changed size");
        assert_eq!(recognizer::ALL.len(), 2, "aa-security's Recognizer set changed size");
    }

    /// An unknown label resolves to `None` rather than to the first variant,
    /// which is what a `find` written as an `unwrap_or_default` would do.
    #[test]
    fn an_unknown_label_resolves_to_none() {
        assert_eq!(severity::from_label("catastrophic"), None);
        assert_eq!(severity::from_label("Critical"), None);
        assert_eq!(confidence::from_label(""), None);
        assert_eq!(recognizer::from_label("aa-gateway::something_new"), None);
    }
}
