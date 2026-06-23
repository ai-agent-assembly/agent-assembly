//! AAASM-3606: the canonical `aa-security::policy::PolicyDocument` must parse
//! every file in the workspace `policy-examples/` directory — the on-disk
//! policy contract that is the single source of truth for both the gateway
//! rule engine and the eBPF map compiler.

#![cfg(feature = "serde")]

use std::path::PathBuf;

use aa_security::policy::PolicyDocument;

/// Resolve the workspace `policy-examples/` directory relative to this crate.
fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("policy-examples")
}

#[test]
fn parses_every_policy_example() {
    let dir = examples_dir();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));

    let mut parsed = 0usize;
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        PolicyDocument::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("canonical parse of {} failed: {e}", path.display()));
        parsed += 1;
    }

    // Guard against a silently-empty directory (which would make the test pass
    // vacuously and hide a regression in the contract location).
    assert!(
        parsed >= 7,
        "expected to parse the full policy-examples corpus, got {parsed}"
    );
}

#[test]
fn strict_example_extracts_canonical_dimensions() {
    let path = examples_dir().join("strict.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap();
    let doc = PolicyDocument::from_yaml(&yaml).unwrap();

    // network egress allowlist is extracted
    assert!(doc.egress_allowlist().contains(&"api.openai.com".to_string()));
    // capability deny floor is extracted
    let denied: Vec<String> = doc.denied_capabilities().iter().map(|c| c.to_string()).collect();
    assert!(denied.contains(&"file_write".to_string()));
    assert!(denied.contains(&"terminal_exec".to_string()));
    // tool wildcard deny is extracted
    assert!(doc.tools.iter().any(|t| t.name == "*" && !t.allow));
}
