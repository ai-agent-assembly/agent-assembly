# Verification Report — AAASM-2618

**Task:** ✅ (aa-runtime): Add runtime-side p99 latency assertion/bench for the scan stage
**Follow-up of:** AAASM-2568 AC4 ("scan-latency metrics emitted; p99 within budget, or budget documented")
**Branch:** `v0.0.1/AAASM-2618/test/runtime_scan_p99` (base `master`)

---

## Context

The authoritative enforcement stage (`aa-runtime/src/pipeline/enforcement.rs`,
`RuntimeScanner::enforce`) already emits the `aa_runtime_scan_latency_seconds`
histogram, but there was **no runtime-side test asserting the scan + redact
p99** — AC4 of AAASM-2568 was satisfied only by the gateway's
`policy_latency_test` and a documented budget. This task adds the missing
runtime-side assertion and records the measured budget.

## Change

A focused latency test at `aa-runtime/tests/scan_latency_test.rs`:

- Sweeps `RuntimeScanner::enforce()` over representative `tool_call.args_json`
  payloads — `small` (256 B), `medium` (4 KiB), and `near_cap` (60 KiB, just
  under the 64 KiB `DEFAULT_MAX_FIELD_BYTES` field cap so the field is scanned
  in full rather than redacted-whole as oversized). Each fixture embeds a real
  credential so the **redaction** path is measured, not a clean no-op scan.
- Records per-call wall-clock latency, sorts, and computes p50/p95/p99/p999/max.
- **Asserts p99 stays within a profile-aware budget** (see below).
- Reuses the gateway's `AA_BENCH_*` env-var convention:
  - `AA_BENCH_SLA_P99_MS` — override the p99 budget (always wins over the default).
  - `AA_BENCH_ITERS` — per-fixture iteration count (default 2 000).

Three `#[test]`s ship: `percentile_picks_expected_rank` (helper),
`fixtures_cover_representative_sizes` (fixture/size guard incl. the near-cap
bound), and `enforce_scan_p99_within_budget` (the assertion).

## Budget rationale

The scan is a pure in-process aho-corasick pass plus redaction — a small
fraction of the gateway's policy-latency budget. The budget is **profile-aware**
because `cargo test` defaults to a debug build where the scanner runs ~100×
slower than the optimized binary the runtime actually ships:

| Profile | Default budget | Measured p99 | Headroom |
|---|---|---|---|
| `--release` | **5 ms** | ~0.37 ms | ~13× |
| debug (default) | **50 ms** | ~2.3 ms | ~21× |

The debug ceiling is loose by design: it still trips on a catastrophic
regression (e.g. an accidental per-event scanner rebuild, or an O(n²) scan)
without flaking under parallel test execution. Set `AA_BENCH_SLA_P99_MS=5` on
bare-metal / nightly runs for a tight check regardless of profile.

## Measured results

**Environment:** Apple M3 Max, 16 cores, 128 GB, macOS 26.4.1 (Darwin 25.4.0),
rustc 1.95.0. 2 000 iterations × 3 fixtures = 6 000 scans, machine otherwise idle.

Release (`cargo test -p aa-runtime --release --test scan_latency_test`):

```
  p50:    22.709µs
  p95:   340.875µs
  p99:   367.625µs
  p999:  472.625µs
  max:   784.667µs
```

Debug (`cargo test -p aa-runtime --test scan_latency_test`):

```
  p50:   183.875µs
  p95:     2.246ms
  p99:     2.334ms
  p999:    2.992ms
  max:     7.905ms
```

The p50/p95 figures are the stable signal; the far tail (p999/max) is dominated
by OS scheduling jitter and grows sharply when the host is contended — hence the
generous, overridable p99 ceiling rather than a tight per-call SLA.

## Verification

```
$ cargo test -p aa-runtime --test scan_latency_test
test percentile_picks_expected_rank ... ok
test fixtures_cover_representative_sizes ... ok
test enforce_scan_p99_within_budget ... ok
test result: ok. 3 passed; 0 failed

$ cargo clippy -p aa-runtime --test scan_latency_test -- -D warnings
Finished — no warnings

$ cargo fmt --check    # clean
```

## Scope

Hardens AC4 coverage of AAASM-2568. The metric + documented budget already
satisfied the AC; this adds the executable assertion and records the
runtime-specific numbers above.
