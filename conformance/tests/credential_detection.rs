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
