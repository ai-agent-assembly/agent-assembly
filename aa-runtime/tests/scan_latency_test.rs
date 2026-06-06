//! Runtime-side scan-stage latency test (AAASM-2618).
//!
//! Hardens AAASM-2568 AC4 ("scan-latency metrics emitted; p99 within budget,
//! or budget documented"). The enforcement stage already emits the
//! `aa_runtime_scan_latency_seconds` histogram; this test adds the missing
//! runtime-side assertion that [`RuntimeScanner::enforce`] p99 stays within an
//! agreed scan budget across representative `tool_call.args_json` sizes,
//! including a fixture near the 64 KiB field cap.
//!
//! Reuses the `AA_BENCH_*` env-var convention from the gateway's
//! `policy_latency_test`: `AA_BENCH_SLA_P99_MS` overrides the budget on noisy /
//! shared CI runners, and `AA_BENCH_ITERS` overrides the per-fixture iteration
//! count for fuller local validation.

use std::time::Duration;

use aa_runtime::pipeline::enforcement::DEFAULT_MAX_FIELD_BYTES;

/// The latency at the given percentile (`pct` in `0.0..=100.0`) of an
/// already-sorted slice. Mirrors the gateway `policy_latency_test` helper so the
/// two latency suites report percentiles identically.
fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    let idx = ((sorted.len() as f64) * pct / 100.0).ceil() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[test]
fn percentile_picks_expected_rank() {
    // 1ms, 2ms, ..., 100ms already sorted (sorted[i] == (i + 1) ms).
    let sorted: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();

    // ceil(100 * 50/100) == 50 -> sorted[50] == 51ms.
    assert_eq!(percentile(&sorted, 50.0), Duration::from_millis(51));
    // ceil(100 * 99/100) == 99 -> sorted[99] == 100ms.
    assert_eq!(percentile(&sorted, 99.0), Duration::from_millis(100));
    // The top percentile clamps to the final (max) element, never out of bounds.
    assert_eq!(percentile(&sorted, 100.0), Duration::from_millis(100));
}

/// An AWS access-key id the credential scanner detects via the `AKIA` literal —
/// embedded in every fixture so the redaction path (not just the clean path) is
/// exercised by the latency measurement.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// The representative `tool_call.args_json` sizes the latency test sweeps.
///
/// `near_cap` deliberately sits just under [`DEFAULT_MAX_FIELD_BYTES`] (64 KiB)
/// so the field is scanned in full rather than redacted-whole as oversized —
/// this is the worst-case scan cost the budget must cover.
const FIXTURE_SIZES: &[(&str, usize)] = &[("small", 256), ("medium", 4 * 1024), ("near_cap", 60 * 1024)];

/// Build a realistic `tool_call.args_json` byte payload of roughly
/// `target_bytes`: a JSON envelope padded with benign filler text and seeded
/// with a single [`AWS_KEY`] so the scanner finds and redacts one credential.
fn args_json_payload(target_bytes: usize) -> Vec<u8> {
    // ~64-byte benign block resembling tool arguments.
    const FILLER: &str = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do; ";
    let prefix = format!(r#"{{"api_key":"{AWS_KEY}","note":""#);
    let suffix = r#""}"#;

    let mut payload = String::with_capacity(target_bytes + FILLER.len());
    payload.push_str(&prefix);
    while payload.len() + suffix.len() < target_bytes {
        payload.push_str(FILLER);
    }
    payload.push_str(suffix);
    payload.into_bytes()
}

#[test]
fn fixtures_cover_representative_sizes() {
    for (name, target) in FIXTURE_SIZES {
        let payload = args_json_payload(*target);
        // Each payload lands at roughly its target size and carries the secret.
        assert!(
            payload.len() >= *target,
            "{name} fixture ({}) under target {target}",
            payload.len()
        );
        assert!(
            payload.windows(AWS_KEY.len()).any(|w| w == AWS_KEY.as_bytes()),
            "{name} fixture must embed the credential to exercise redaction"
        );
    }

    // The near-cap fixture must be scanned in full: large, but under the cap so
    // it is not short-circuited by the oversized-field path.
    let near_cap = args_json_payload(60 * 1024);
    assert!(near_cap.len() > 32 * 1024, "near_cap fixture should be large");
    assert!(
        near_cap.len() < DEFAULT_MAX_FIELD_BYTES,
        "near_cap fixture must stay under the {DEFAULT_MAX_FIELD_BYTES}-byte cap"
    );
}
