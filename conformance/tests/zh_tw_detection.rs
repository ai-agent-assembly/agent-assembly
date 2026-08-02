//! Conformance tests for the zh-TW locale recognizer pack (AAASM-5353).
//!
//! Each JSON vector in `vectors/zh_tw_detection/` is driven against
//! `aa_security::locale::zh_tw::scan()` and
//! `aa_security::canonical::redact_findings()`.
//!
//! These are a **separate** vector directory from `credential_detection/`, and
//! deliberately so. Those 34 vectors describe `CredentialScanner::scan()`, which
//! this ticket does not touch — `scanner.rs` differs from the base branch by a
//! doc comment and one visibility keyword — so keeping the two suites apart is
//! what makes "all existing vectors pass unchanged" a structural fact rather
//! than a claim to re-verify. It also keeps the Python SDK runner, which drives
//! only `credential_detection/`, from being handed a schema it cannot evaluate.

use aa_security::canonical::{redact_findings, CanonicalCategory};
use aa_security::locale::zh_tw;
use aa_security::CredentialScanner;
use conformance::{load_vectors, LocaleScanVector};

fn load_locale_vectors() -> Vec<LocaleScanVector> {
    load_vectors("vectors/zh_tw_detection")
}

/// The suite must actually contain vectors, and both polarities of them.
///
/// A directory that failed to load, or that held only negatives, would make
/// every assertion below pass over an empty or one-sided set. That is the exact
/// shape of a vacuous suite.
#[test]
fn the_vector_suite_is_non_empty_and_two_sided() {
    let vectors = load_locale_vectors();
    assert!(vectors.len() >= 10, "expected a real suite, got {}", vectors.len());

    let positives = vectors.iter().filter(|v| !v.expected_findings.is_empty()).count();
    let negatives = vectors.len() - positives;
    assert!(positives >= 6, "too few positive vectors: {positives}");
    assert!(negatives >= 4, "too few negative vectors: {negatives}");

    // And every category the positives name is one this build can parse. A
    // vector naming a category that does not exist would fail loudly below, but
    // a *typo* in one that does exist would silently test nothing.
    for vector in &vectors {
        for finding in &vector.expected_findings {
            assert!(
                finding.category.parse::<CanonicalCategory>().is_ok(),
                "vector '{}' names a category this build cannot parse: {}",
                vector.description,
                finding.category
            );
        }
    }
}

#[test]
fn all_vectors_have_correct_finding_count() {
    for v in load_locale_vectors() {
        let found = zh_tw::scan(&v.input_text);
        assert_eq!(
            found.len(),
            v.expected_findings.len(),
            "vector '{}': expected {} findings, got {:?}",
            v.description,
            v.expected_findings.len(),
            found
                .iter()
                .map(|f| (f.category().to_string(), f.span().start(), f.span().end()))
                .collect::<Vec<_>>()
        );
    }
}

/// Category, span and confidence, in offset order.
///
/// The `end` offset is checked as well as the start, because the boundary rule
/// is the load-bearing part of a CJK recognizer: a span that swallowed the Han
/// character after the identifier would still start in the right place.
#[test]
fn all_vectors_have_correct_categories_spans_and_confidence() {
    for v in load_locale_vectors() {
        let found = zh_tw::scan(&v.input_text);
        for (i, expected) in v.expected_findings.iter().enumerate() {
            let actual = found.get(i).unwrap_or_else(|| {
                panic!(
                    "vector '{}': finding {i} missing (expected {})",
                    v.description, expected.category
                )
            });
            assert_eq!(
                actual.category().to_string(),
                expected.category,
                "vector '{}': finding {i} category mismatch",
                v.description
            );
            assert_eq!(
                (actual.span().start(), actual.span().end()),
                (expected.offset, expected.end),
                "vector '{}': finding {i} span mismatch over {:?}",
                v.description,
                v.input_text
            );
            assert_eq!(
                actual.confidence().as_str(),
                expected.confidence,
                "vector '{}': finding {i} confidence mismatch",
                v.description
            );
        }
    }
}

#[test]
fn all_vectors_redact_correctly() {
    for v in load_locale_vectors() {
        let redacted = redact_findings(&v.input_text, &zh_tw::scan(&v.input_text));
        assert_eq!(
            redacted, v.expected_redacted,
            "vector '{}': redacted output mismatch\n  got:      {}\n  expected: {}",
            v.description, redacted, v.expected_redacted
        );
    }
}

/// Every span a vector pins must fall on a character boundary of its own text.
///
/// This is what makes the full-width vector meaningful rather than decorative: a
/// full-width digit is three UTF-8 bytes, so a span computed over normalised
/// digits would land mid-character, and `redact_findings` would fail closed and
/// blank the whole payload instead of replacing the identifier.
#[test]
fn every_expected_span_is_a_character_boundary() {
    let mut checked = 0usize;
    for v in load_locale_vectors() {
        for f in &v.expected_findings {
            assert!(
                v.input_text.is_char_boundary(f.offset) && v.input_text.is_char_boundary(f.end),
                "vector '{}': span {}..{} is not on a character boundary",
                v.description,
                f.offset,
                f.end
            );
            assert!(f.end > f.offset, "vector '{}': empty span", v.description);
            checked += 1;
        }
    }
    assert!(checked >= 6, "too few spans checked to prove anything: {checked}");
}

/// No raw identifier survives redaction of a positive vector.
///
/// Span equality is the precise assertion; this is the one that matters. It
/// checks the property directly rather than by proxy, so it still holds if the
/// expected-output strings and the implementation ever drift together.
#[test]
fn no_identifier_survives_redaction() {
    let mut checked = 0usize;
    for v in load_locale_vectors() {
        let redacted = redact_findings(&v.input_text, &zh_tw::scan(&v.input_text));
        for f in &v.expected_findings {
            let raw = &v.input_text[f.offset..f.end];
            assert!(
                !redacted.contains(raw),
                "vector '{}': {raw:?} survived redaction",
                v.description
            );
            checked += 1;
        }
    }
    assert!(checked >= 6, "too few identifiers checked: {checked}");
}

/// The locale pack is what found these — the credential scanner finds nothing in
/// any of them.
///
/// Without this, a vector could be passing because some *other* detector
/// happened to fire, and the suite would not distinguish the two. It is also the
/// direct statement of the additive property: these payloads were previously
/// passed through untouched.
#[test]
fn the_credential_scanner_finds_nothing_in_any_locale_vector() {
    let scanner = CredentialScanner::new();
    for v in load_locale_vectors() {
        let result = scanner.scan(&v.input_text);
        assert!(
            result.is_clean(),
            "vector '{}': the credential scanner produced {:?}, so this vector does not \
             isolate the locale pack",
            v.description,
            result.findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>()
        );
    }
}
