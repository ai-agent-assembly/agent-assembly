//! The frozen runtime verdict, as an event field.

// Only the `Deserialize` impl below constructs a `String`, and that impl is
// `#[cfg(feature = "serde")]`. Left unconditional this is an `unused_imports`
// error on any crate selection that omits the feature — which `--all-features`
// hides, because there every gate is open (AAASM-5682).
#[cfg(feature = "serde")]
use alloc::string::String;

/// The enforcement outcome an action received, spelled exactly as ADR 0018's
/// `RuntimeVerdict` spells it.
///
/// # Why this is not an enum
///
/// ADR 0032 D-2 freezes `aa_api::models::verdict::RuntimeVerdict` — its five
/// variants are not added to, renamed or reordered, because ADR 0024 establishes
/// that adding an enum variant is not additive on the wire. AAASM-5355 is
/// forbidden from defining a competing outcome enum, and it does not.
///
/// It also cannot simply *use* `RuntimeVerdict`: that type lives in `aa-api`,
/// which depends on `aa-core`, and ADR 0018 put it there deliberately so it
/// could carry a `utoipa::ToSchema` derive. The dependency will not be inverted
/// for an event field.
///
/// So the event carries the verdict's **wire label** rather than a second copy
/// of the vocabulary. A newtype over `&'static str` with five associated
/// constants is not a competing enum in the way a parallel `enum` would be: it
/// cannot be `match`ed exhaustively, it has no variants to reorder, and it
/// cannot acquire a sixth meaning without someone editing a list that says in
/// its own documentation that the list is frozen. `aa-gateway` already writes
/// this verdict as a lowercase string for exactly the same reason
/// (`service/convert.rs`), so the label — not the Rust type — is what actually
/// crosses layers today.
///
/// # The seam AAASM-5356 fills
///
/// D-2's finer vocabulary — `redact` · `mask` · `tokenize` · `require_approval`
/// · `approval_granted` · `approval_denied` · `shadow_only` · `none` — is a
/// **separate optional** `sensitive_data_disposition` field on
/// [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent), and it is
/// AAASM-5356's deliverable, not this one's. Three things here exist to keep
/// that addition easy and honest:
///
/// - The event is `#[non_exhaustive]` and built through a builder, so a new
///   optional field is additive for every constructor.
/// - The schema rule ignores minor versions, so a `1.1` writer's event is
///   readable by a `1.0` reader ([`SchemaVersion`](super::SchemaVersion)).
/// - Nothing in this module consults the verdict to decide whether an action is
///   permitted, and nothing may consult the disposition either. Both are
///   *records of* an authorisation decision `aa-gateway` already made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuntimeVerdictLabel(&'static str);

impl RuntimeVerdictLabel {
    /// Action permitted unchanged.
    pub const ALLOW: Self = Self("allow");
    /// Action permitted but scoped down.
    pub const NARROW: Self = Self("narrow");
    /// Action permitted, payload stripped of secrets or PII en route.
    pub const SCRUB: Self = Self("scrub");
    /// Action held awaiting human approval.
    pub const PENDING: Self = Self("pending");
    /// Action blocked outright.
    pub const DENY: Self = Self("deny");

    /// Every verdict ADR 0018 defines, in the order it defines them.
    ///
    /// Five, permanently. A sixth entry here would be a breaking wire change
    /// under ADR 0024 and a violation of ADR 0032 D-2.
    ///
    /// # This list is a mirror, and `aa-api` enforces the reflection
    ///
    /// `aa_api::models::verdict::RuntimeVerdict` is the authority; these are its
    /// wire labels, maintained by hand. The two are tied together by
    /// `aa_api::models::verdict::aa_core_label_contract`, which asserts that
    /// each variant serializes to exactly the entry of this list at the same
    /// index (AAASM-5384). A rename, reorder, addition or removal on either
    /// side now fails that test instead of silently breaking every stored
    /// [`SensitiveDataDecisionEvent`](super::SensitiveDataDecisionEvent).
    ///
    /// The test lives in `aa-api` — the only crate that can see both types —
    /// rather than here, because `aa-core` cannot import `aa-api`: that
    /// dependency runs the other way, deliberately (ADR 0018). So editing this
    /// list alone still builds and tests clean *within this crate*; it is
    /// `cargo nextest run -p aa-api` that objects.
    pub const ALL: &'static [Self] = &[Self::ALLOW, Self::NARROW, Self::SCRUB, Self::PENDING, Self::DENY];

    /// Read a verdict back from its wire label.
    ///
    /// Returns `None` for anything else rather than inventing a verdict. An
    /// unrecognised outcome is a recorded failure, never a permissive default —
    /// the same rule ADR 0032 §5 applies to detection, for the same reason.
    pub fn from_wire(label: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|verdict| verdict.0 == label)
    }

    /// The wire label, which is the whole contract.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// Whether this verdict satisfies ADR 0032 §8's *second* condition for
    /// counting an event as prevented transmission: the decision was a deny or
    /// a transforming disposition.
    ///
    /// True for [`DENY`](Self::DENY) and [`SCRUB`](Self::SCRUB) only. `NARROW`
    /// scopes the action rather than transforming the payload, `PENDING` has
    /// not decided anything yet, and `ALLOW` is the absence of a restriction.
    ///
    /// This is **reporting, not authorisation.** Nothing may call it to decide
    /// whether an action is permitted; it answers one clause of a metric
    /// predicate, and on its own it is not enough to claim prevention — see
    /// [`SensitiveDataDecisionEvent::counts_as_prevented_transmission`](super::SensitiveDataDecisionEvent::counts_as_prevented_transmission)
    /// for the other three conditions.
    pub fn is_deny_or_transforming(&self) -> bool {
        *self == Self::DENY || *self == Self::SCRUB
    }
}

impl core::fmt::Display for RuntimeVerdictLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RuntimeVerdictLabel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RuntimeVerdictLabel {
    /// Resolves against [`ALL`](RuntimeVerdictLabel::ALL) rather than leaking a
    /// runtime string into a `&'static str`.
    ///
    /// `Box::leak` would make an arbitrary wire value into a verdict in safe
    /// stable Rust, which is the hole `aa-security`'s `CategoryQualifier`
    /// documents and closes the same way.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let label = String::deserialize(deserializer)?;
        Self::from_wire(&label).ok_or_else(|| {
            // The label is echoed because a verdict is a closed five-value
            // vocabulary, not caller data — there is nothing sensitive it can
            // hold, and a reader needs to know what it choked on.
            D::Error::custom(alloc::format!(
                "not one of the five ADR 0018 runtime verdicts: {label:?}"
            ))
        })
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for RuntimeVerdictLabel {
    fn schema_name() -> alloc::borrow::Cow<'static, str> {
        "RuntimeVerdictLabel".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "enum": ["allow", "narrow", "scrub", "pending", "deny"],
            "description": "ADR 0018 runtime verdict, as its wire label.",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vocabulary, pinned to exactly five labels with exactly these
    /// spellings.
    ///
    /// This is the ADR 0032 D-2 acceptance criterion in test form. A sixth
    /// entry or a respelling is a breaking wire change under ADR 0024, and the
    /// dashboard keys its verdict styling off these strings — so a "tidy-up"
    /// rename would silently unstyle the UI as well as break every stored
    /// event.
    #[test]
    fn the_verdict_vocabulary_is_exactly_adr_0018s_five_labels() {
        let labels: alloc::vec::Vec<&str> = RuntimeVerdictLabel::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(labels, ["allow", "narrow", "scrub", "pending", "deny"]);
    }

    /// An unknown outcome is refused, not defaulted. A verdict that fell back
    /// to `allow` on an unparseable label would turn a read error into a
    /// permissive-looking record.
    #[test]
    fn an_unknown_label_is_refused_rather_than_defaulted() {
        assert_eq!(RuntimeVerdictLabel::from_wire("redact"), None);
        assert_eq!(RuntimeVerdictLabel::from_wire("Allow"), None);
        assert_eq!(RuntimeVerdictLabel::from_wire(""), None);
        assert_eq!(
            RuntimeVerdictLabel::from_wire("allow"),
            Some(RuntimeVerdictLabel::ALLOW)
        );
    }

    /// Only a deny or a payload transformation can support a prevention claim.
    ///
    /// `NARROW` is the trap: it *sounds* restrictive, but it scopes the action
    /// rather than stopping the payload, so counting it would inflate the
    /// prevention metric with actions that were carried out.
    #[test]
    fn only_deny_and_scrub_satisfy_the_transforming_condition() {
        assert!(RuntimeVerdictLabel::DENY.is_deny_or_transforming());
        assert!(RuntimeVerdictLabel::SCRUB.is_deny_or_transforming());
        assert!(!RuntimeVerdictLabel::NARROW.is_deny_or_transforming());
        assert!(!RuntimeVerdictLabel::PENDING.is_deny_or_transforming());
        assert!(!RuntimeVerdictLabel::ALLOW.is_deny_or_transforming());
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// The serialized form is the label itself, matching what `aa-api`'s
    /// `RuntimeVerdict` emits with `serde(rename_all = "lowercase")` and what
    /// `aa-gateway` already writes. If these two ever disagree, a stored event
    /// stops deserializing on the read side.
    #[test]
    fn a_verdict_serializes_as_its_lowercase_label() {
        for verdict in RuntimeVerdictLabel::ALL {
            assert_eq!(
                serde_json::to_string(verdict).unwrap(),
                alloc::format!("\"{}\"", verdict.as_str())
            );
        }
    }

    #[test]
    fn a_verdict_round_trips() {
        for verdict in RuntimeVerdictLabel::ALL {
            let json = serde_json::to_string(verdict).unwrap();
            let restored: RuntimeVerdictLabel = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, verdict);
        }
    }

    /// Deserialization refuses an unknown label instead of leaking it into a
    /// `&'static str`, which is what a grammar-driven parse would need to do.
    #[test]
    fn deserializing_an_unknown_label_fails() {
        assert!(serde_json::from_str::<RuntimeVerdictLabel>(r#""redact""#).is_err());
        assert!(serde_json::from_str::<RuntimeVerdictLabel>(r#""blocked""#).is_err());
    }
}
