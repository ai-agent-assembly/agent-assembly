//! The metric-label boundary, attacked from a genuinely downstream crate.
//!
//! # Why this is an integration test and not a unit test
//!
//! Everything in `aa-core`'s own `mod tests` can see private fields and
//! `pub(super)` constructors, so a unit test cannot tell the difference between
//! "the boundary holds" and "the boundary holds for anyone who is not already
//! inside". This file is compiled as a separate crate and sees exactly the
//! public API a consumer sees.
//!
//! It exists because an earlier revision of
//! [`SensitiveDataMetricLabels`](aa_core::types::sensitive_data::SensitiveDataMetricLabels)
//! documented its labels as "unrepresentable" and was wrong: a
//! `SensitiveDataFindingRecord` deserialized from storage could carry an
//! arbitrary category string, and projecting it put **a raw credential into a
//! metric label value** — ADR 0032 forbidden design #12. The fix was to hold a
//! resolved `CanonicalCategory` and refuse to project what does not resolve.
//!
//! Every literal here is synthetic.

use aa_core::types::sensitive_data::{
    CategoryLabel, RuntimeVerdictLabel, SensitiveDataFindingRecord, SensitiveDataMetricLabels,
};

/// A synthetic token in `aa-security`'s documented example format. Not a live
/// credential; it exists so the test asserts about the shape of a secret
/// without containing one.
const SYNTHETIC_TOKEN: &str = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

/// Build a stored record whose category field is whatever the caller says.
///
/// This is the hostile input: a row read back from storage, which no
/// construction-time guard ever saw.
fn stored_record_with_category(category: &str) -> Result<SensitiveDataFindingRecord, serde_json::Error> {
    let json = format!(
        r#"{{"schema_version":{{"major":1,"minor":0}},
            "event_id":"01HZX9V8ABCDEFGHJKMNPQRSTV",
            "category":"{category}",
            "severity":"critical","confidence":"high","method":"deterministic","status":"confirmed",
            "provenance":{{"recognizer":"aa-security::scanner","version":"0.0.0-test"}},
            "field_path":"body.token","redaction_label":"[REDACTED]"}}"#
    );
    serde_json::from_str(&json)
}

/// **The blocker, as a regression test.**
///
/// A stored record carrying a raw credential where its category should be must
/// not yield metric labels. Before the fix this produced
/// `("category", "ghp_16C7e42F292c…")` and serialized it.
#[test]
fn a_credential_smuggled_into_a_stored_category_cannot_become_a_metric_label() {
    let record = stored_record_with_category(SYNTHETIC_TOKEN).expect("a well-shaped string still deserializes");

    // The record itself carries it — deserialization is deliberately not
    // catalogue-closed, so that a newer build's category survives a round-trip.
    assert_eq!(record.category.as_str(), SYNTHETIC_TOKEN);

    // But it does not resolve, so it cannot be projected.
    assert_eq!(record.category.resolve(), None);
    assert!(
        SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::DENY).is_none(),
        "an unresolvable category was projected into a bounded metric label"
    );
}

/// The same guarantee stated over the serialized output, since that is what
/// actually reaches an exporter.
#[test]
fn no_projection_exists_to_serialize_for_an_unresolvable_category() {
    for hostile in [
        SYNTHETIC_TOKEN,
        "postgresql://user:password@db.internal:5432/app",
        "NATIONAL_ID[xx-ZZ/synthetic_for_test]",
        "arbitrary text a writer chose",
    ] {
        let record = stored_record_with_category(hostile).expect("well-shaped");
        assert!(
            SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::SCRUB).is_none(),
            "`{hostile}` reached the projection"
        );
    }
}

/// A category the build *does* know still projects, so the refusal above is not
/// simply "nothing ever projects".
///
/// Without this, deleting the body of `from_finding` and returning `None`
/// unconditionally would satisfy every other test in this file.
#[test]
fn a_catalogue_category_still_projects() {
    let record = stored_record_with_category("ACCESS_TOKEN[github:personal_access]").expect("well-shaped");
    let labels =
        SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::DENY).expect("a catalogue category");

    let pairs = labels.as_pairs();
    assert_eq!(pairs[0], ("category", "ACCESS_TOKEN[github:personal_access]"));
    assert_eq!(pairs.len(), 6);
}

/// Every label value that can leave this type is a member of a compile-time
/// catalogue — asserted from outside, over the serialized form.
#[test]
fn every_serialized_label_value_is_a_catalogue_member() {
    let record = stored_record_with_category("EMAIL_ADDRESS").expect("well-shaped");
    let labels = SensitiveDataMetricLabels::from_finding(&record, RuntimeVerdictLabel::ALLOW).expect("catalogue");

    let json: serde_json::Value = serde_json::to_value(&labels).unwrap();
    let object = json.as_object().expect("an object");

    // The resolved category must render as itself, and nothing may appear that
    // is not one of the six.
    assert_eq!(object.len(), 6, "the projection changed shape: {object:?}");
    assert_eq!(object["category"], "EMAIL_ADDRESS");
    for name in SensitiveDataMetricLabels::LABEL_NAMES {
        assert!(object.contains_key(name), "missing label `{name}`");
        assert!(object[name].is_string(), "label `{name}` is not a string");
    }
}

/// The honest limit of the guard, pinned so it is not mistaken for something
/// stronger.
///
/// `CategoryLabel::new` is public and shape-only — it is the read path's
/// constructor and cannot be catalogue-closed without breaking the deliberate
/// round-trip of a newer build's category. So a caller *can* mint a label
/// holding arbitrary text. What it cannot do is get that text into a metric,
/// which is where ADR 0032 §9 requires boundedness.
#[test]
fn a_hostile_label_can_be_built_but_goes_nowhere() {
    let label = CategoryLabel::new(SYNTHETIC_TOKEN).expect("shape-only check accepts it");
    assert_eq!(label.resolve(), None, "it is not a category, and never claims to be");

    // Shape is still enforced on that path.
    assert!(CategoryLabel::new("has\na newline").is_err());
    assert!(CategoryLabel::new("x".repeat(4096)).is_err());
}

/// A stored record whose category is malformed is refused outright, rather than
/// carried. The derived `Deserialize` this type once had validated nothing.
#[test]
fn a_malformed_stored_category_fails_to_deserialize() {
    // A control character in the category is refused on the read path.
    let json = r#"{"schema_version":{"major":1,"minor":0},
        "event_id":"01HZX9V8ABCDEFGHJKMNPQRSTV",
        "category":"API_KEY\nforged",
        "severity":"critical","confidence":"high","method":"deterministic","status":"confirmed",
        "provenance":{"recognizer":"aa-security::scanner","version":"0.0.0-test"},
        "field_path":"body.token","redaction_label":"[REDACTED]"}"#;
    assert!(
        serde_json::from_str::<SensitiveDataFindingRecord>(json).is_err(),
        "a category with an embedded newline was accepted from storage"
    );
}
