//! Conformance tests for credential detection.
//!
//! Each JSON vector in `vectors/credential_detection/` is loaded and driven
//! against `CredentialScanner::scan()` and `ScanResult::redact()`.

use aa_security::CredentialScanner;
use conformance::{load_vectors, ScanVector};

fn scanner() -> CredentialScanner {
    CredentialScanner::new()
}

/// Load all scan vectors from the credential_detection directory.
fn load_scan_vectors() -> Vec<ScanVector> {
    load_vectors("vectors/credential_detection")
}

#[test]
fn all_vectors_have_correct_finding_count() {
    let sc = scanner();
    for v in load_scan_vectors() {
        let result = sc.scan(&v.input_text);
        assert_eq!(
            result.findings.len(),
            v.expected_findings.len(),
            "vector '{}': expected {} findings, got {}",
            v.description,
            v.expected_findings.len(),
            result.findings.len()
        );
    }
}

#[test]
fn all_vectors_have_correct_finding_kinds() {
    let sc = scanner();
    for v in load_scan_vectors() {
        let result = sc.scan(&v.input_text);
        for (i, expected) in v.expected_findings.iter().enumerate() {
            let actual = result.findings.get(i).unwrap_or_else(|| {
                panic!(
                    "vector '{}': finding index {} missing (expected kind '{}')",
                    v.description, i, expected.kind
                )
            });
            assert_eq!(
                actual.kind.as_str(),
                expected.kind,
                "vector '{}': finding {} kind mismatch",
                v.description,
                i
            );
        }
    }
}

#[test]
fn all_vectors_have_correct_finding_offsets() {
    let sc = scanner();
    for v in load_scan_vectors() {
        let result = sc.scan(&v.input_text);
        for (i, expected) in v.expected_findings.iter().enumerate() {
            let actual = result.findings.get(i).unwrap_or_else(|| {
                panic!(
                    "vector '{}': finding index {} missing (expected offset {})",
                    v.description, i, expected.offset
                )
            });
            assert_eq!(
                actual.offset, expected.offset,
                "vector '{}': finding {} offset mismatch",
                v.description, i
            );
        }
    }
}

#[test]
fn all_vectors_redact_correctly() {
    let sc = scanner();
    for v in load_scan_vectors() {
        let result = sc.scan(&v.input_text);
        let redacted = result.redact(&v.input_text);
        assert_eq!(
            redacted, v.expected_redacted,
            "vector '{}': redacted output mismatch\n  got:      {}\n  expected: {}",
            v.description, redacted, v.expected_redacted
        );
    }
}

// ── SDK-bypass resistance: encoded / nested payloads (AAASM-2634 / Story AAASM-2569 case 3) ──
//
// The gateway's banned-key sanitizer strips *known key names*; it never inspects
// values hidden under unknown keys, deep nesting, or arbitrary surrounding text.
// The `CredentialScanner` that `aa-runtime` runs authoritatively is content-based,
// so position / nesting / key-name confers no immunity. These tests assert
// **raw-secret-absence** after `redact()` — the secret substring never survives —
// rather than finding-count or label equality, per the known scanner-overlap quirk
// where a single secret can match several detectors.

/// An AWS access-key id — detected via the `AKIA` literal pattern.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

#[test]
fn nested_json_secret_is_redacted() {
    let sc = scanner();
    // A secret buried four objects deep: a key-based strip never reaches it.
    let input = serde_json::json!({
        "a": { "b": { "c": { "credential": AWS_KEY } } }
    })
    .to_string();

    let result = sc.scan(&input);
    assert!(
        !result.is_clean(),
        "a secret nested deep in JSON must still be detected"
    );
    let redacted = result.redact(&input);
    assert!(
        !redacted.contains(AWS_KEY),
        "raw secret must not survive redaction even when deeply nested"
    );
}
