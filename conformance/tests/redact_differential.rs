//! Differential: the Python conformance runner's `_redact` vs `ScanResult::redact`.
//!
//! Why this exists
//! ---------------
//! `conformance/runner/runner.py::_redact` reconstructs the redacted string an
//! SDK is expected to produce, and it only means anything if it agrees with the
//! reference implementation it claims to mirror. Everything else that checks it
//! — the unit tests, the legacy sweep in `check_redact_equivalence.py` — compares
//! it against a model of Rust written in Python. A model can be wrong in exactly
//! the way the implementation is wrong, and then both agree and neither is right.
//!
//! This drives the **real** `ScanResult::redact` and the **real** `_redact` over
//! the same span geometries and compares them byte for byte. It is the only
//! check in the tree that does.
//!
//! `conformance/runner/` has no CI of its own (AAASM-5374): `conformance-python`
//! is `continue-on-error: true` and invokes none of those files. This test runs
//! in the ordinary Rust suite, so the Python runner's central claim is covered by
//! something that actually gates.
//!
//! Covering the priority path
//! --------------------------
//! `CredentialFinding::from_regex_match` always yields `CredentialKind::Custom`,
//! so a harness built only from it gives every finding priority 2 and the label
//! `[REDACTED:Custom]` — which never exercises label selection, the mechanism
//! that stops a real credential being downgraded to `GenericHighEntropy` when
//! two detectors overlap. `kind` and `matched` are public, so this sets them
//! after construction and mixes priorities deliberately (AAASM-5373).
//!
//! Fixtures are synthetic. No real credential material appears here or in the
//! generated spans, which are pure geometry over placeholder text.

use aa_security::{CredentialFinding, CredentialKind, ScanResult};
use std::io::Write;
use std::process::{Command, Stdio};

/// Texts chosen so byte offsets and code-point offsets cannot coincide, and so
/// there are interior positions that are *not* character boundaries.
const TEXTS: &[&str] = &[
    "abcdefghij",
    "key=SECRET-VALUE-123",
    "番号=1234",
    "メモ token=abc",
    "aあb",
];

/// The kinds whose relative `priority()` decides which label a merged span keeps:
/// two generic backstops (0 and 1) and two specific detectors (both 2).
fn kinds() -> [CredentialKind; 4] {
    [
        CredentialKind::GenericHighEntropy,
        CredentialKind::EmailAddress,
        CredentialKind::PostgresUrl,
        CredentialKind::AwsAccessKey,
    ]
}

/// Build a finding with an arbitrary span *and* an arbitrary kind.
///
/// `end` is private, so the span has to come from the public
/// `from_regex_match`; `kind` and `matched` are public and are overwritten so
/// the finding carries the label `CredentialFinding::new` would have built.
fn finding(kind: &CredentialKind, offset: usize, end: usize) -> CredentialFinding {
    let mut f = CredentialFinding::from_regex_match(offset, end);
    f.matched = format!("[REDACTED:{}]", kind.as_str());
    f.kind = kind.clone();
    f
}

/// Mirror of the private `CredentialKind::priority()` (scanner.rs:334-368), used
/// only to classify generated cases. Counting "the two kinds differ" instead
/// would call `PostgresUrl` vs `AwsAccessKey` a priority conflict when both
/// score 2 and no label swap can occur.
fn priority_of(kind: &str) -> u8 {
    match kind {
        "GenericHighEntropy" => 0,
        "EmailAddress" => 1,
        _ => 2,
    }
}

struct Case {
    text: &'static str,
    spans: Vec<(usize, usize, String)>,
}

/// Every span geometry that matters, over every text.
///
/// Deliberately includes spans that are out of range, inverted, and starting or
/// ending inside a multi-byte character — those are the fail-closed cases, and a
/// generator that emits only `0 <= offset <= end <= n` would leave the whole
/// fail-closed contract unexercised.
fn cases() -> Vec<Case> {
    let ks = kinds();
    let mut out = Vec::new();
    for text in TEXTS {
        let n = text.len(); // bytes
        let positions: Vec<usize> = (0..=n + 2).collect();

        // One span, every (offset, end) pair including inverted and past the end.
        for (i, &o) in positions.iter().enumerate() {
            for &e in &positions {
                let k = &ks[i % ks.len()];
                out.push(Case {
                    text,
                    spans: vec![(o, e, k.as_str().to_string())],
                });
            }
        }

        // Two spans: disjoint, adjacent (o2 == e1), overlapping, and nested —
        // each with a mix of kinds so the priority tie-breaks are exercised.
        for &o1 in &positions {
            for &e1 in &positions {
                for &o2 in &positions {
                    for len2 in [0usize, 1, 3] {
                        let e2 = o2 + len2;
                        for (ka, kb) in [(0, 1), (0, 2), (2, 0), (1, 2), (2, 3)] {
                            out.push(Case {
                                text,
                                spans: vec![
                                    (o1, e1, ks[ka].as_str().to_string()),
                                    (o2, e2, ks[kb].as_str().to_string()),
                                ],
                            });
                        }
                    }
                }
            }
        }

        // Three overlapping spans of mixed priority: the case where the merged
        // span's label is decided by a finding that is neither first nor last.
        for &o1 in &positions {
            for &o2 in &positions {
                for &o3 in &positions {
                    out.push(Case {
                        text,
                        spans: vec![
                            (o1, o1 + 4, ks[0].as_str().to_string()),
                            (o2, o2 + 6, ks[2].as_str().to_string()),
                            (o3, o3 + 2, ks[1].as_str().to_string()),
                        ],
                    });
                }
            }
        }
    }
    out
}

fn rust_redact(case: &Case) -> String {
    let findings = case
        .spans
        .iter()
        .map(|(o, e, k)| {
            let kind = kinds().iter().find(|c| c.as_str() == k).expect("kind in table").clone();
            finding(&kind, *o, *e)
        })
        .collect();
    ScanResult { findings }.redact(case.text)
}

/// Run every case through the Python `_redact` in one subprocess.
fn python_redact(cases: &[Case]) -> Vec<String> {
    let payload: Vec<serde_json::Value> = cases
        .iter()
        .map(|c| {
            serde_json::json!({
                "text": c.text,
                "spans": c.spans.iter().map(|(o, e, k)| serde_json::json!({
                    "kind": k, "offset": o, "end": e,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let runner_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/runner");
    let script = r#"
import json, sys
sys.path.insert(0, sys.argv[1])
from runner import _redact
cases = json.load(sys.stdin)
print(json.dumps([_redact(c["text"], c["spans"]) for c in cases]))
"#;

    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(runner_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        // Not skipped when python3 is missing: a differential that quietly
        // becomes a no-op is the failure mode this whole ticket family is about.
        .expect("python3 is required to run the redaction differential");

    let body = serde_json::to_vec(&payload).expect("serialise cases");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&body)
        .expect("write cases");

    let out = child.wait_with_output().expect("run python3");
    assert!(
        out.status.success(),
        "python3 _redact failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse python output")
}

#[test]
fn python_redact_matches_rust_over_every_span_geometry() {
    let cases = cases();
    let python = python_redact(&cases);
    assert_eq!(python.len(), cases.len(), "one python result per case");

    let mut failclosed = 0usize;
    let mut adjacent = 0usize;
    let mut overlapping = 0usize;
    let mut mixed_priority = 0usize;
    let mut mismatch_count = 0usize;
    let mut mismatches = Vec::new();

    for (case, py) in cases.iter().zip(&python) {
        let rs = rust_redact(case);
        if rs == "[REDACTED]" {
            failclosed += 1;
        }
        let mut sorted = case.spans.clone();
        sorted.sort_by_key(|(o, e, _)| (*o, *e));
        for w in sorted.windows(2) {
            if w[1].0 < w[0].1 {
                overlapping += 1;
                if priority_of(&w[0].2) != priority_of(&w[1].2) {
                    mixed_priority += 1;
                }
            } else if w[1].0 == w[0].1 && w[0].0 < w[0].1 {
                adjacent += 1;
            }
        }
        if &rs != py {
            mismatch_count += 1;
            // Only the first few are kept for the message; the count above is
            // the real total, so a failure never understates how wrong it is.
            if mismatches.len() < 10 {
                mismatches.push(format!(
                    "text={:?} spans={:?}\n  rust  ={:?}\n  python={:?}",
                    case.text, case.spans, rs, py
                ));
            }
        }
    }

    // Counts are asserted, not just printed. A generator that stopped emitting
    // one of these shapes would leave the corresponding branch unexercised while
    // the test still reported success.
    assert!(failclosed > 1000, "too few fail-closed cases: {failclosed}");
    assert!(adjacent > 1000, "too few adjacent-span cases: {adjacent}");
    assert!(overlapping > 1000, "too few overlapping cases: {overlapping}");
    assert!(
        mixed_priority > 1000,
        "too few mixed-priority overlaps: {mixed_priority}"
    );

    assert!(
        mismatches.is_empty(),
        "{} of {} cases differ from ScanResult::redact (first {} shown)\n{}",
        mismatch_count,
        cases.len(),
        mismatches.len(),
        mismatches.join("\n")
    );

    eprintln!(
        "compared {} cases: {failclosed} fail-closed, {adjacent} adjacent, \
         {overlapping} overlapping ({mixed_priority} mixed-priority)",
        cases.len()
    );
}
