//! The rendered canonical category, as it appears in a record.

use alloc::string::{String, ToString};

use aa_security::canonical::CanonicalCategory;

use super::guard::{check_shape, FieldRejection, MAX_LABEL_BYTES};

/// A canonical category in its rendered `BASE` or `BASE[qualifier]` form.
///
/// # Why a record stores the rendering and not the category
///
/// Not a stylistic choice — `aa-security`'s [`CanonicalCategory`] implements
/// `Serialize` and deliberately **not** `Deserialize`, so that a finding is
/// never reconstructed from bytes but always derived from something the process
/// detected. A record that has to round-trip through storage therefore cannot
/// hold one directly, and `aa-core` cannot add the missing impl: both the type
/// and the trait are foreign.
///
/// So a record stores what `Display` produced. That is not a downgrade: ADR
/// 0032 §2 makes the rendered form *the* contract, which is why AAASM-5352
/// hand-wrote `Serialize` to emit exactly it.
///
/// # Reading one back, and the reader that is deliberately absent
///
/// [`resolve`](Self::resolve) returns `Option<CanonicalCategory>`, `None` for a
/// category this build does not know — a locale category from AAASM-5353 read
/// by a build that predates it, say.
///
/// `aa-security`'s `ParseCategoryError::UnknownCategory` records that a weaker,
/// display-only reader — a `parse_base` handing back `NATIONAL_ID` from
/// `NATIONAL_ID[zh-TW/arc_new]` — would belong with this ticket's projection if
/// one were wanted. **It is not added, and the reasoning is worth keeping.**
///
/// - Nothing needs it. The dashboard renders a category; it does not have to
///   understand one. [`as_str`](Self::as_str) hands over the rendered string
///   verbatim, which displays a category from a newer build *perfectly* — better
///   than a partial parse, which would show `NATIONAL_ID` and silently discard
///   the jurisdiction that says what the finding means.
/// - Adding it here would put a second parser for `aa-security`'s vocabulary in
///   a different crate, free to drift from the catalogue it mirrors.
/// - `aa-core` is not only read by dashboards. A `parse_base` sitting in the
///   shared domain crate is reachable from an enforcement path, and a partial
///   category is exactly the confident-looking wrong answer ADR 0032 §5 exists
///   to prevent.
///
/// If a concrete reader ever needs base-level routing, the honest place for it
/// is `aa-security` beside the catalogue, named so it says it is doing
/// something weaker — not here, and not before there is a caller.
///
/// # Unknown labels survive
///
/// Deserialization accepts any well-shaped label, including one this build
/// cannot resolve. An audit record read by an older build must round-trip
/// intact; dropping a field because the reader is behind the writer loses data
/// permanently, and the record is the evidence.
///
/// # Wire format
///
/// Serializes transparently as the rendered string:
///
/// ```json
/// "ACCESS_TOKEN[github:personal_access]"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct CategoryLabel(String);

impl CategoryLabel {
    /// Accept a label read from storage, or say why not.
    ///
    /// Prefer [`From<CanonicalCategory>`](#impl-From<CanonicalCategory>) when
    /// the category is in hand — it cannot fail and cannot produce a label
    /// outside this build's catalogue. This constructor exists for the read
    /// path, where the label came from a record rather than from a detector.
    ///
    /// # Errors
    ///
    /// [`FieldRejection::Empty`], [`FieldRejection::TooLong`] past
    /// [`MAX_LABEL_BYTES`](super::MAX_LABEL_BYTES), or
    /// [`FieldRejection::ControlCharacter`]. Not screened with the credential
    /// scanner: a rendered category is generated from a compiled-in catalogue,
    /// never lifted out of scanned bytes.
    pub fn new(label: impl Into<String>) -> Result<Self, FieldRejection> {
        let label = label.into();
        check_shape(&label, MAX_LABEL_BYTES)?;
        Ok(Self(label))
    }

    /// The rendered category, exactly as written.
    ///
    /// Always safe to display, including for a category this build does not
    /// know — which is the whole reason no partial parse is offered.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The category this label names, or `None` if this build has never heard
    /// of it.
    ///
    /// `None` is not an error to paper over: it means a newer build produced
    /// the record. Display the label, do not guess at the category.
    pub fn resolve(&self) -> Option<CanonicalCategory> {
        self.0.parse().ok()
    }
}

impl From<CanonicalCategory> for CategoryLabel {
    fn from(category: CanonicalCategory) -> Self {
        Self(category.to_string())
    }
}

impl core::fmt::Display for CategoryLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every category this build can produce survives the round-trip through a
    /// record and back.
    ///
    /// This is the fidelity claim the whole design rests on — if rendering and
    /// resolving are not inverse, a stored event names a category that cannot
    /// be read back. It also demonstrates the bounded cardinality ADR 0032 §9
    /// requires of a metric label: the label domain *is*
    /// `CanonicalCategory::ALL`, a compile-time list.
    #[test]
    fn every_known_category_round_trips_through_its_label() {
        for category in CanonicalCategory::ALL {
            let label = CategoryLabel::from(*category);
            assert_eq!(
                label.resolve(),
                Some(*category),
                "category {label} did not resolve back to itself"
            );
        }
        assert!(
            !CanonicalCategory::ALL.is_empty(),
            "an empty catalogue would make this vacuous"
        );
    }

    /// A locale-qualified category this build does not know resolves to `None`
    /// and — the part that matters — is **not** degraded to its base.
    ///
    /// This is the shape AAASM-5353's locale packs have. A reader that answered
    /// `NATIONAL_ID` here would be discarding the jurisdiction, which is what
    /// says whether the finding is a residence certificate or something else
    /// entirely. This test is the record of that decision: add a partial parse
    /// and it fails.
    ///
    /// The locale is deliberately synthetic (`xx-ZZ`, a reserved-for-private-use
    /// tag) rather than a real one. A real locale would stop being unknown the
    /// moment a locale pack landed, and this test would then be asserting the
    /// opposite of what it was written to assert.
    #[test]
    fn an_unknown_category_resolves_to_none_and_is_never_degraded_to_its_base() {
        let rendered = "NATIONAL_ID[xx-ZZ/synthetic_for_test]";
        let label = CategoryLabel::new(rendered).unwrap();

        assert!(
            label.as_str().starts_with("NATIONAL_ID"),
            "the base is plainly legible in the rendering — that is what makes the temptation real"
        );
        assert_eq!(
            label.resolve(),
            None,
            "a legible base must still not be handed back as a partial category"
        );
        assert_eq!(label.as_str(), rendered, "the full rendering survives for display");
    }

    /// The label is displayable whatever it holds — the property that makes a
    /// weaker display-only parser unnecessary.
    #[test]
    fn an_unresolvable_label_still_displays_verbatim() {
        let label = CategoryLabel::new("SOMETHING_THIS_BUILD_HAS_NEVER_SEEN[xx-YY/whatever]").unwrap();
        assert_eq!(
            alloc::format!("{label}"),
            "SOMETHING_THIS_BUILD_HAS_NEVER_SEEN[xx-YY/whatever]"
        );
    }

    #[test]
    fn a_malformed_label_is_refused() {
        assert_eq!(CategoryLabel::new(""), Err(FieldRejection::Empty));
        assert_eq!(CategoryLabel::new("API\nKEY"), Err(FieldRejection::ControlCharacter));
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// The label serializes to the same string `aa-security` emits for the
    /// category itself, so a record's category field and a canonical finding's
    /// category field are the same bytes. If they diverged, an event and the
    /// audit-tier finding it came from would disagree about what was found.
    #[test]
    fn a_label_serializes_identically_to_the_category_it_came_from() {
        for category in CanonicalCategory::ALL {
            let label = CategoryLabel::from(*category);
            assert_eq!(
                serde_json::to_string(&label).unwrap(),
                serde_json::to_string(category).unwrap(),
                "label and category serialized differently for {category}"
            );
        }
    }

    /// A record written by a newer build survives being read and written again
    /// by an older one. Dropping the field would lose it permanently.
    #[test]
    fn an_unknown_label_round_trips_intact() {
        // Synthetic locale, for the same reason as the resolve test: a real one
        // stops being unknown as soon as a locale pack ships.
        let json = r#""NATIONAL_ID[xx-ZZ/synthetic_for_test]""#;
        let label: CategoryLabel = serde_json::from_str(json).unwrap();
        assert_eq!(label.resolve(), None);
        assert_eq!(serde_json::to_string(&label).unwrap(), json);
    }
}
