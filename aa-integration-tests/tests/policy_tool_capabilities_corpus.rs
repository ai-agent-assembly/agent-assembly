//! One corpus, three verdicts, for `tools.<name>.capabilities` (AAASM-6259).
//!
//! The declaration is read by three independently-written gates: the public
//! JSON schema (`schemas/policy/v1/policy-document.schema.json`), the gateway
//! validator (`aa_policy`) and the canonical parser (`aa_security`). They live
//! in crates that cannot see each other, so a word added to one list and not the
//! others would silently make a policy valid for one consumer and refused by
//! another. Only a test that feeds the same YAML to all three can catch that.
//!
//! Every accepted row has a rejected row that differs in one respect.

use aa_gateway::policy::PolicyValidator;
use aa_security::policy::PolicyDocument as CanonicalDocument;
use serde_json::Value;

fn schema() -> Value {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../schemas/policy/v1/policy-document.schema.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("read schema")).expect("schema is JSON")
}

fn doc(tool: &str, caps: &str) -> String {
    format!("tools:\n  {tool}:\n    allow: true\n    capabilities: {caps}\n")
}

/// `(label, tool key, capabilities value, accepted by all three)`.
const CORPUS: &[(&str, &str, &str, bool)] = &[
    (
        "spec example: egress + name resolution",
        "web_search",
        "[network_egress, name_resolution]",
        true,
    ),
    (
        "spec example: filesystem_write",
        "write_note",
        "[filesystem_write]",
        true,
    ),
    ("spec example: none", "calculator", "[none]", true),
    ("filesystem_read", "t", "[filesystem_read]", true),
    ("ipc", "t", "[ipc]", true),
    ("credential", "t", "[credential]", true),
    ("process_creation passes authoring", "t", "[process_creation]", true),
    ("syscall passes authoring", "t", "[syscall]", true),
    ("empty list", "t", "[]", false),
    ("unknown word", "t", "[teleport]", false),
    ("wrong case", "t", "[Network_Egress]", false),
    ("duplicate word", "t", "[ipc, ipc]", false),
    ("duplicate none", "t", "[none, none]", false),
    ("none then another", "t", "[none, ipc]", false),
    ("another then none", "t", "[ipc, none]", false),
    ("resource is launch-boundary", "t", "[resource]", false),
    (
        "workspace_transaction is launch-boundary",
        "t",
        "[workspace_transaction]",
        false,
    ),
    ("launch-boundary beside a valid word", "t", "[ipc, resource]", false),
    ("scalar instead of list", "t", "ipc", false),
    ("nested list", "t", "[[ipc]]", false),
    ("number in list", "t", "[1]", false),
    ("wildcard tool key with valid words", "\"*\"", "[ipc]", false),
    // `capabilities:` with nothing after it is not "undeclared": all three
    // gates refuse a bare key rather than read it as omitted.
    ("null instead of a list", "t", "null", false),
];

/// Whole `tools` entries (not just the capabilities value), including the
/// wildcard key. Added because splitting the wildcard entry off the shared
/// per-tool schema once left `"*"` unvalidated by the schema.
const TOOL_ENTRIES: &[(&str, &str, bool)] = &[
    ("wildcard allow true", "tools:\n  \"*\":\n    allow: true\n", true),
    (
        "wildcard with limit",
        "tools:\n  \"*\":\n    allow: true\n    limit_per_hour: 5\n",
        true,
    ),
    (
        "wildcard non-boolean allow",
        "tools:\n  \"*\":\n    allow: banana\n",
        false,
    ),
    (
        "wildcard unknown key",
        "tools:\n  \"*\":\n    allow: true\n    bogus: 1\n",
        false,
    ),
    ("named non-boolean allow", "tools:\n  t:\n    allow: banana\n", false),
    (
        "named unknown key",
        "tools:\n  t:\n    allow: true\n    bogus: 1\n",
        false,
    ),
];

#[test]
fn schema_validator_and_canonical_parser_agree_on_every_corpus_row() {
    let schema = schema();
    for (label, tool, caps, accepted) in CORPUS {
        let yaml = doc(tool, caps);
        let instance: Value = serde_yaml::from_str(&yaml).expect("corpus row is YAML");

        let by_schema = jsonschema::is_valid(&schema, &instance);
        let by_validator = PolicyValidator::from_yaml(&yaml).is_ok();
        let by_canonical = CanonicalDocument::from_yaml(&yaml).is_ok();

        assert_eq!(
            (by_schema, by_validator, by_canonical),
            (*accepted, *accepted, *accepted),
            "[{label}] (schema, aa-policy, aa-security) for:\n{yaml}"
        );
    }
}

#[test]
fn schema_validator_and_canonical_parser_agree_on_every_tool_entry() {
    let schema = schema();
    for (label, yaml, accepted) in TOOL_ENTRIES {
        let instance: Value = serde_yaml::from_str(yaml).expect("row is YAML");
        let got = (
            jsonschema::is_valid(&schema, &instance),
            PolicyValidator::from_yaml(yaml).is_ok(),
            CanonicalDocument::from_yaml(yaml).is_ok(),
        );
        assert_eq!(
            got,
            (*accepted, *accepted, *accepted),
            "[{label}] (schema, aa-policy, aa-security) for:\n{yaml}"
        );
    }
}

/// The corpus is not vacuous: it contains both verdicts, so a gate that accepts
/// or rejects everything cannot satisfy it.
#[test]
fn the_corpus_has_both_accepted_and_rejected_rows() {
    assert!(CORPUS.iter().any(|r| r.3));
    assert!(CORPUS.iter().any(|r| !r.3));
}

/// A plain wildcard entry stays valid on all three gates; only a declaration
/// under it is refused, so the wildcard row above is rejected for the key.
#[test]
fn a_wildcard_tool_without_a_declaration_is_still_accepted_everywhere() {
    let yaml = "tools:\n  \"*\":\n    allow: true\n";
    let instance: Value = serde_yaml::from_str(yaml).unwrap();
    assert!(jsonschema::is_valid(&schema(), &instance));
    assert!(PolicyValidator::from_yaml(yaml).is_ok());
    assert!(CanonicalDocument::from_yaml(yaml).is_ok());
}

/// A declaration grants nothing and lowers nothing: the validated document's
/// canonical projection and lease list are identical with and without it.
#[test]
fn a_declaration_changes_neither_the_canonical_projection_nor_the_leases() {
    let bare = "network:\n  allowlist: [a.example]\ntools:\n  t:\n    allow: true\n";
    let declared = "network:\n  allowlist: [a.example]\ntools:\n  t:\n    allow: true\n    capabilities: [network_egress, process_creation]\n";
    let bare = PolicyValidator::from_yaml(bare).unwrap().document;
    let declared = PolicyValidator::from_yaml(declared).unwrap().document;

    assert_eq!(bare.to_canonical(), declared.to_canonical());
    assert_eq!(bare.to_canonical_leases(), declared.to_canonical_leases());
    assert!(declared.leases.is_empty());
}
