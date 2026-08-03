//! The wire contract for the additive `sensitiveDataDisposition` field
//! (AAASM-5356, ADR 0032 §10 D-2).
//!
//! Two properties are asserted here that cannot be asserted inside
//! `models::disposition`, because both are about the *published artifact* rather
//! than the Rust type:
//!
//! 1. **Adding the field changed nothing for a client that ignores it.** A
//!    decision row with no disposition serializes byte-for-byte as it did before
//!    the field existed, and a pre-change payload still deserializes.
//! 2. **The disposition is never an input.** It appears only in response bodies
//!    of the generated `openapi/v1.yaml` — never in a request body or a query
//!    parameter — so no caller can hand the server a disposition for it to act
//!    on. This is the structural half of ADR 0032 §10 D-2's "not a second
//!    authorisation channel"; the other half is that `aa-gateway` and
//!    `aa-runtime` sit *below* `aa-api` in the dependency graph and so cannot
//!    name the type at all.
//!
//! The spec is read from the committed `openapi/v1.yaml` on purpose, not from
//! `ApiDoc::openapi()`: the committed file is what the dashboard's
//! `openapi-typescript` codegen and every external client build from, and CI's
//! drift gate already proves the two agree.

use aa_api::models::disposition::SensitiveDataDisposition;
use aa_api::routes::agents::{AgentDecisionResponse, DecisionLabel};
use serde_json::Value;

/// Exactly what `GET /api/v1/agents/{id}/decisions` emitted for this row before
/// `sensitiveDataDisposition` existed.
///
/// A literal rather than a value derived from the current struct — deriving it
/// would make the comparison below tautological, which is the whole failure mode
/// this file exists to rule out. Regenerating this string from the post-change
/// type would be the way to make the test pass while breaking the contract.
const PRE_CHANGE_DECISION_ROW: &str = concat!(
    r#"{"timestamp":"2026-08-01T09:15:00+00:00","sessionId":"0a0b","seq":7,"#,
    r#""verb":"TOOL_CALL","resource":"api.example.test","decision":1,"#,
    r#""decisionLabel":"allow","verdict":"allow","traceId":null,"#,
    r#""matchedPolicy":"rule-egress-a","latencyMs":12}"#,
);

/// The same row as [`PRE_CHANGE_DECISION_ROW`], as the current type.
fn decision_row(disposition: Option<SensitiveDataDisposition>) -> AgentDecisionResponse {
    AgentDecisionResponse {
        timestamp: "2026-08-01T09:15:00+00:00".to_string(),
        session_id: "0a0b".to_string(),
        seq: 7,
        verb: Some("TOOL_CALL".to_string()),
        resource: Some("api.example.test".to_string()),
        decision: 1,
        decision_label: DecisionLabel::Allow,
        verdict: Some(aa_api::models::verdict::RuntimeVerdict::Allow),
        trace_id: None,
        matched_policy: Some("rule-egress-a".to_string()),
        latency_ms: Some(12),
        sensitive_data_disposition: disposition,
    }
}

/// A row with no disposition serializes to the pre-change bytes — same keys,
/// same order, no `"sensitiveDataDisposition": null` appended.
///
/// This is ADR 0032 §10 D-2's first binding rule in its strongest form: absence
/// is not "a new key set to null", it is the key not being there. Byte equality
/// rather than `serde_json::Value` equality, because a value comparison would
/// pass with the key order changed and clients that parse incrementally, or diff
/// recorded fixtures, would still see a changed response.
#[test]
fn a_row_without_a_disposition_is_byte_identical_to_the_pre_change_response() {
    let serialized = serde_json::to_string(&decision_row(None)).unwrap();
    assert_eq!(serialized, PRE_CHANGE_DECISION_ROW);
}

/// A payload written before the field existed still deserializes, and reads back
/// as "no disposition".
///
/// The old-server half of the compatibility statement: a stored or replayed
/// pre-change row must not become unreadable, and its missing key must mean
/// absent — never a default that claims something happened.
#[test]
fn a_pre_change_payload_deserializes_with_the_disposition_absent() {
    let row: AgentDecisionResponse = serde_json::from_str(PRE_CHANGE_DECISION_ROW).unwrap();

    assert_eq!(row.sensitive_data_disposition, None);
    // Everything a pre-change client reads is unchanged, above all the
    // authoritative outcome.
    assert_eq!(row.verdict, Some(aa_api::models::verdict::RuntimeVerdict::Allow));
    assert_eq!(row.seq, 7);
    assert_eq!(row.matched_policy.as_deref(), Some("rule-egress-a"));

    // And it round-trips back to the same bytes it arrived as.
    assert_eq!(serde_json::to_string(&row).unwrap(), PRE_CHANGE_DECISION_ROW);
}

/// When a disposition *is* present the response is the pre-change object with
/// one key appended — nothing existing moves, changes name, or changes value.
#[test]
fn a_present_disposition_is_a_pure_suffix_append() {
    let serialized = serde_json::to_string(&decision_row(Some(SensitiveDataDisposition::Redact))).unwrap();

    let expected = format!(
        "{}{}",
        PRE_CHANGE_DECISION_ROW.strip_suffix('}').unwrap(),
        r#","sensitiveDataDisposition":"redact"}"#,
    );
    assert_eq!(serialized, expected);

    // A client that ignores the unknown key reads the pre-change object back.
    let mut object: serde_json::Map<String, Value> = serde_json::from_str(&serialized).unwrap();
    assert!(object.remove("sensitiveDataDisposition").is_some());
    assert_eq!(
        Value::Object(object),
        serde_json::from_str::<Value>(PRE_CHANGE_DECISION_ROW).unwrap()
    );
}

/// An explicit `"none"` and an absent key say the same thing about the record.
///
/// They are not the same *bytes* — `none` is a positive statement that the
/// pipeline had nothing to report, absence is the field never having been
/// written — but neither may change the conclusion a reader draws, which is that
/// `verdict` carries the whole meaning.
#[test]
fn an_explicit_none_and_an_absent_key_imply_the_same_verdict() {
    let absent = decision_row(None);
    let explicit = decision_row(Some(SensitiveDataDisposition::None));

    assert_eq!(absent.verdict, explicit.verdict);
    assert_eq!(SensitiveDataDisposition::None.implied_verdict(), None);
}

/// The committed spec every client builds from.
fn committed_spec() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../openapi/v1.yaml");
    let yaml = std::fs::read_to_string(path).expect("openapi/v1.yaml is committed");
    serde_yaml::from_str(&yaml).expect("openapi/v1.yaml parses")
}

/// Every `$ref` target name anywhere under `node`.
fn referenced_schema_names(node: &Value, out: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    if let Some(name) = value.as_str().and_then(|r| r.rsplit('/').next()) {
                        out.push(name.to_string());
                    }
                }
                referenced_schema_names(value, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| referenced_schema_names(item, out)),
        _ => {}
    }
}

/// Whether `node` contains the literal string `needle` anywhere.
fn contains_string(node: &Value, needle: &str) -> bool {
    match node {
        Value::String(s) => s == needle,
        Value::Object(map) => map.values().any(|v| contains_string(v, needle)),
        Value::Array(items) => items.iter().any(|v| contains_string(v, needle)),
        _ => false,
    }
}

/// The disposition schema, and every schema that can reach it, appear in no
/// request body and no parameter of the published spec.
///
/// This is the structural reason the field cannot become a second authorisation
/// channel *from outside*: there is no request shape in which a caller can send
/// one, so there is nothing for the server to consult. (The reason it cannot
/// become one from inside is the dependency direction — `aa-gateway` and
/// `aa-runtime` cannot import `aa-api`, so the code that decides cannot name the
/// type.)
///
/// Both a named `$ref` and an inlined copy are checked: utoipa inlines some
/// schemas, and an inlined enum would carry the eight spellings with no `$ref`
/// to find.
#[test]
fn the_disposition_is_never_a_request_input() {
    let spec = committed_spec();

    // Which component schemas can reach SensitiveDataDisposition — computed
    // rather than listed, so a new response type embedding it is covered the day
    // it is added.
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("the spec has component schemas");
    let mut tainted: Vec<String> = vec!["SensitiveDataDisposition".to_string()];
    loop {
        let mut grew = false;
        for (name, schema) in schemas {
            if tainted.iter().any(|t| t == name) {
                continue;
            }
            let mut refs = Vec::new();
            referenced_schema_names(schema, &mut refs);
            if refs.iter().any(|r| tainted.iter().any(|t| t == r)) {
                tainted.push(name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    // Anti-vacuity: the closure must have found the response that carries the
    // field. If the field were dropped from every response this test would
    // otherwise pass by scanning for a type nothing uses.
    assert!(
        tainted.iter().any(|t| t == "AgentDecisionResponse"),
        "AgentDecisionResponse no longer reaches SensitiveDataDisposition; the field \
         is not on the response it is supposed to be on. Tainted set: {tainted:?}",
    );
    assert!(
        tainted.iter().any(|t| t == "AgentDecisionsResponse"),
        "AgentDecisionsResponse no longer reaches SensitiveDataDisposition",
    );

    let mut request_shapes_scanned = 0usize;
    for (path, item) in spec["paths"].as_object().expect("the spec has paths") {
        for (method, operation) in item.as_object().expect("a path item is a map") {
            for input_kind in ["requestBody", "parameters"] {
                let Some(input) = operation.get(input_kind) else {
                    continue;
                };
                request_shapes_scanned += 1;

                let mut refs = Vec::new();
                referenced_schema_names(input, &mut refs);
                for reference in &refs {
                    assert!(
                        !tainted.iter().any(|t| t == reference),
                        "{method} {path} accepts {reference} as a {input_kind}, which reaches \
                         SensitiveDataDisposition — the disposition must never be an input \
                         (ADR 0032 §10 D-2)",
                    );
                }

                // An inlined enum would have no $ref to catch. `require_approval`
                // is unique to this vocabulary, so its presence in a request
                // shape means the disposition was inlined into one.
                assert!(
                    !contains_string(input, "require_approval"),
                    "{method} {path} inlines the disposition vocabulary into a {input_kind}",
                );
            }
        }
    }

    // Anti-vacuity: the spec really does have request shapes, so the loop above
    // asserted something.
    assert!(
        request_shapes_scanned > 50,
        "only {request_shapes_scanned} request shapes scanned — the scan is not \
         reaching the spec's inputs",
    );
}

/// The published schema is optional, carries all eight spellings, and lives on
/// the decision record.
#[test]
fn the_published_schema_is_optional_and_carries_the_eight_spellings() {
    let spec = committed_spec();

    let published: Vec<&str> = spec["components"]["schemas"]["SensitiveDataDisposition"]["enum"]
        .as_array()
        .expect("SensitiveDataDisposition is published as an enum schema")
        .iter()
        .map(|v| v.as_str().expect("a string enum value"))
        .collect();
    assert_eq!(
        published,
        [
            "redact",
            "mask",
            "tokenize",
            "require_approval",
            "approval_granted",
            "approval_denied",
            "shadow_only",
            "none",
        ],
    );

    let decision_row = &spec["components"]["schemas"]["AgentDecisionResponse"];
    assert!(
        decision_row["properties"].get("sensitiveDataDisposition").is_some(),
        "AgentDecisionResponse does not publish sensitiveDataDisposition",
    );

    // Optional: an existing client that does not send or expect it stays valid.
    let required: Vec<&str> = decision_row["required"]
        .as_array()
        .map(|s| s.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    assert!(
        !required.contains(&"sensitiveDataDisposition"),
        "the disposition is a required property; it must be additive and optional",
    );
    // Anti-vacuity: this response does have required properties, so the check
    // above is reading a real list.
    assert!(required.contains(&"timestamp"), "required list not found: {required:?}");
}
