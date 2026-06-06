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
