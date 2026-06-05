# AAASM-2574 — Verification: build-time baseline acceptance criteria

Verifies the parent Story **AAASM-2557** (_Establish build-time baseline_,
Epic **AAASM-2551**), implemented in **AAASM-2573** (PR #928 — harness
`scripts/build-baseline.sh`, `make build-baseline`, and
`docs/src/benchmarks/build-time-baseline.md`).

## How verified

Ran the harness independently from a clean worktree (empty `target/`, so a
genuine cold build) on the same class of machine, and cross-checked the output
against the numbers recorded by AAASM-2573:

| # | Method |
|---|--------|
| 1 | `make build-baseline` (→ `bash scripts/build-baseline.sh`) — fresh cold build, warm rebuild, test-binary build (`--no-run`), `cargo tree -d` |
| 2 | Confirmed `target/build-baseline/cargo-timing.html` is generated and the top-crate extraction is non-empty |
| 3 | Re-computed the `cargo tree -d` duplicate metric and compared to the recorded baseline |

Host: Apple M-series (arm64), macOS Darwin 25.4.0, `cargo 1.95.0`,
`cargo-nextest 0.9.133`. `aa-ebpf` excluded (nightly + `bpf-linker`), matching
`make build-workspace` / `make test`.

## Reproduced numbers vs recorded baseline

| Measurement | Recorded (AAASM-2573) | Reproduced (this run) | Agreement |
|---|---|---|---|
| Cold build (`build --workspace --timings`) | 124 s | 69 s | Same order of magnitude (see variance note) |
| Warm rebuild (touch `aa-cli/src/main.rs`) | 5 s | 5 s | Exact |
| Test build (`nextest run --no-run`) | 396 s | 363 s | Within ~8 % |
| Packages built in >1 version (`cargo tree -d`) | 34 | 34 | Exact |
| Distinct duplicate `(name, version)` units | 105 | 105 | Exact |

The **deterministic** metrics (test-binary compile, duplicate counts, and the
set of long-pole crates) reproduce tightly. Cold-build wall-clock is the only
high-variance figure — now observed across four runs at **69 / 91 / 124 / 211 s**
on this machine — which confirms the doc's caveat that the cold build is noisy
locally and that per-Story before/after pairs must be captured on the same idle
machine, with CI treated as authoritative.

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Baseline numbers for cold build, warm rebuild, and test build+run recorded | ✅ Pass | Recorded in `docs/src/benchmarks/build-time-baseline.md` (cold/warm/test-build wall-clock table) and reproduced above; the full Docker-backed `build+run` (3452 s, run-dominated) is captured in the "Full test build+run (context)" note. |
| `cargo build --timings` HTML identifies the top 5 longest-compiling crates | ✅ Pass | `cargo-timing.html` archived and parsed; reproduced top set `aws-lc-sys`, `cranelift-codegen`, `wasmtime`, `wasmparser`, `zstd-sys` — the WASM + crypto long poles (per-crate seconds reorder with parallelism, the set is stable). |
| `cargo tree -d` attached as the dedup baseline for AAASM-2555 | ✅ Pass | **34** packages built in >1 version (worst: `hashbrown` ×4; `rand`/`rand_core`/`getrandom` ×3) reproduced exactly; full report archived at `target/build-baseline/cargo-tree-dups.txt`. |

## Verdict

**All three acceptance criteria are met.** The harness is reproducible, the
recorded numbers hold (within documented local variance), and the baseline is
ready for the profile (AAASM-2553), dev/linker (AAASM-2554), dedup
(AAASM-2555), and CI (AAASM-2556) Stories to re-measure against.
