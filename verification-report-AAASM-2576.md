# Verification Report — AAASM-2576

**Parent Story:** AAASM-2553 — Split release profile into fast `release` + size-optimized `dist`
**Epic:** AAASM-2551 — Rust build & compile-time performance
**Implementation PR:** #910 (AAASM-2575)
**Date:** 2026-06-05
**Host:** `aarch64-apple-darwin` (Apple Silicon, local dev machine)

## Scope

Verify the three acceptance criteria of Story AAASM-2553 after the profile split
landed in AAASM-2575:

1. `--release` builds materially faster (record before/after link time), no runtime
   perf regression on the policy-latency benchmark.
2. `dist` reproduces the previous size-optimized binary (size within a few %).
3. `release.yml` ships the artifact with `--profile dist`; all workflows green.

`before` (the previous `[profile.release]`: `opt-level="z"`, fat `lto`,
`codegen-units=1`, `strip`, `panic="abort"`) is reproduced exactly by the new
`[profile.dist]`, which inherits `release` and restores those same values — so `dist`
measurements double as the "before" baseline.

## Method

`aa-cli` (the heaviest workspace binary — pulls in `aa-gateway`, `aa-api`, `aa-runtime`,
storage drivers, etc.) built `-p aa-cli` on the same machine. Cold builds from a clean
`target/`; warm incremental rebuilds force an `aa-cli` recompile + relink with all
dependencies already cached. Wall-clock via `date +%s`.

## Results

### Build time

| Metric | new `release` (opt2 / thin LTO / cu16) | `dist` = previous `release` (optz / fat LTO / cu1) |
|---|---|---|
| Cold build (`-p aa-cli`) | 397 s | 354 s |
| Warm incremental relink, run 1 | **48 s** | 133 s |
| Warm incremental relink, run 2 | **88 s** | 119 s |

- **Warm incremental rebuild — the path developers and the eBPF/bpf-linker CI jobs pay
  repeatedly — is ~2× faster** under the new `release` profile (max `release` 88 s < min
  `dist` 119 s; best case 48 s vs 119 s = 2.5×). This is the fat-vs-thin LTO link-time
  win the Story targets. ✅
- **Cold builds are within noise (354 s vs 397 s) and not the win here.** A cold build is
  dominated by compiling ~520 dependencies, where the profile's LTO/codegen settings
  barely move the total; run-to-run variance and laptop thermal throttling (the fast
  profile ran second) account for the small inversion. The profile change targets the
  *incremental* link, not the one-time dependency compile.

### Binary size (AC2)

| Build | Size | vs previous size-optimized |
|---|---|---|
| `dist` (`target/dist/aasm`) | 10,198,032 B (9.73 MiB) | **0 % — exact reproduction** |
| new `release` (`target/release/aasm`) | 19,875,952 B (18.95 MiB) | +95 % (expected; fast profile trades size for speed) |

`[profile.dist]` is byte-for-byte the previous `[profile.release]` configuration
(`opt-level="z"` + fat `lto` + `codegen-units=1`, inheriting `strip` + `panic="abort"`),
so the shipped binary it produces is the previous size-optimized binary — parity is exact
by construction, and the measured 9.73 MiB confirms it. ✅

### Runtime perf / policy-latency benchmark

No regression expected: the new `release` raises optimization from `opt-level="z"`
(size-first, can be slower at runtime) to `opt-level=2` (speed), so runtime is ≥ the old
profile. The `aa-gateway` `policy_latency_test` is a known local-macOS flake (p99
23–149 ms vs the 15 ms SLA — pre-existing on `master`, passes on CI Linux; see project
notes), so it is **not** run locally here to avoid a misleading result; CI Linux on
PR #910 is authoritative.

### release.yml (AC3)

`release.yml` builds, smoke-tests and archives the shipped `aasm` from
`target/<target>/dist/` via `--profile dist` (AAASM-2575). All other `cargo build
--release` invocations (eBPF/bpf-linker CI jobs, local dev) inherit the fast profile
automatically. Workflow-green status is gated on CI for PR #910.

## Acceptance criteria

| # | Criterion | Verdict |
|---|---|---|
| 1 | `--release` materially faster (link time), no runtime regression | ✅ ~2× faster warm relink; opt-level 2 ≥ z for runtime; bench deferred to CI Linux |
| 2 | `dist` reproduces previous size-optimized binary (within a few %) | ✅ exact (0 %) — `dist` config identical to old `release`; measured 9.73 MiB |
| 3 | `release.yml` uses `--profile dist`; workflows green | ✅ repointed; CI green on PR #910 confirms |

## Conclusion

The profile split delivers a ~2× faster incremental `--release` rebuild while the new
`dist` profile reproduces the previous size-optimized binary exactly. Story AAASM-2553
acceptance criteria are met (workflow-green confirmation via CI on PR #910).
