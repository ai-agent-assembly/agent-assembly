# Performance Benchmark Baseline

Baseline results recorded on 2026-04-29.
Machine: Apple M-series (arm64), macOS Darwin 25.2.0.

All benchmarks run with `cargo bench` in release profile.

## SDK Hook Overhead (`aa-ffi-python`)

Target: < 2 ms P99 per LLM call (AAASM-34 AC #6).

| Benchmark | Mean | Low | High |
|---|---|---|---|
| `report_llm_call_channel` | 237 ns | 229 ns | 245 ns |

**Verdict: PASS** — 3 orders of magnitude below the 2 ms target.

> **Note (AAASM-2562):** the `aa-ffi-python` SDK-hook benchmark (`sdk_bench`) moved
> to the `python-sdk` repo when the fat binding left this workspace — run it there
> with `cargo bench --bench sdk_bench`. The numbers above are retained as the
> historical 2026-04-29 baseline.

## Proxy Intercept Latency (`aa-proxy`)

Target: < 5 ms P99 per intercepted request (AAASM-36 AC #5).

| Benchmark | Mean | Low | High |
|---|---|---|---|
| `intercept/openai_response` | 2.74 us | 2.74 us | 2.75 us |
| `intercept/openai_with_credential_redaction` | 3.82 us | 3.79 us | 3.86 us |

**Verdict: PASS** — both variants well below the 5 ms target.
Credential redaction adds ~1 us overhead.

## Gateway Policy Check (`aa-gateway`)

| Benchmark | Mean | Low | High |
|---|---|---|---|
| `check_action_rpc/round_trip/minimal_llm_call` | 79.6 us | 78.8 us | 80.5 us |
| `check_action_rpc/round_trip/full_tool_call_1kb` | 79.6 us | 78.3 us | 80.9 us |
| `check_action_rpc/round_trip/worst_case_network` | 76.3 us | 75.6 us | 76.9 us |

## Credential Scanner Throughput (`aa-core`)

| Benchmark | Mean | Throughput |
|---|---|---|
| `scanner/scan_1mb_payload` | 6.31 ms | ~159 MB/s |

## Comparing Against Baseline

Run `cargo bench` to generate HTML reports in `target/criterion/`.
Each benchmark group produces a `report/index.html` with historical
comparison charts when prior runs exist.

To compare against this baseline:

1. Run `cargo bench` on the baseline commit to populate `target/criterion/`.
2. Run `cargo bench` on the new commit — Criterion auto-compares and reports
   percentage change with statistical significance.
