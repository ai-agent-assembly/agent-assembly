# Build-Time Baseline

Before/after harness for **Epic AAASM-2551** (_Rust build & compile-time
performance_). This page records the **build-time** baseline established by
Story **AAASM-2557** so the profile (AAASM-2553), dev/linker (AAASM-2554),
dependency-dedup (AAASM-2555), and CI (AAASM-2556) Stories can each quote a
measured before/after against the **same** harness.

> This is distinct from [Baseline](BASELINE.md), which records **runtime**
> (`cargo bench`) numbers. This page measures how long the workspace takes to
> **compile**, not how fast it runs.

## Harness

Run the full capture with:

```bash
make build-baseline          # wraps scripts/build-baseline.sh
# or
bash scripts/build-baseline.sh
```

The harness records four measurements and archives the raw outputs (logs, the
`cargo build --timings` HTML, the top-crate extraction, and the `cargo tree -d`
report) under `target/build-baseline/` (gitignored):

| # | Measurement | Command |
|---|---|---|
| 1 | Cold build | `cargo clean` then `cargo build --workspace --timings` |
| 2 | Warm rebuild | `touch aa-cli/src/main.rs` then `cargo build --workspace` |
| 3 | Test build | `cargo nextest run --workspace --no-run` (compile only) |
| 4 | Duplicate deps | `cargo tree -d` |

Measurement 3 deliberately compiles the test binaries **without running**
them: the build-time signal the profile/linker/dedup Stories move is the
**compile** cost, whereas the full suite's run wall-clock is dominated by
Docker-backed integration tests and is sensitive to timing flakes. Set
`BUILD_BASELINE_RUN_TESTS=1` to additionally run the full suite
(`--no-fail-fast`) and record its build+run wall-clock.

### Why `aa-ebpf` is excluded

`aa-ebpf` requires a nightly toolchain plus `bpf-linker`, so the workspace's own
`make build-workspace` and `make test` targets build with `--exclude aa-ebpf`.
The baseline mirrors that to measure the build path developers and the
non-eBPF CI jobs actually hit. Pass `BUILD_BASELINE_INCLUDE_EBPF=1` to include
it on a nightly-capable host. Other tunables: `BUILD_BASELINE_WARM_FILE`,
`BUILD_BASELINE_TOP_N`, `BUILD_BASELINE_OUT` (see the script header).

### Reproducibility notes

- Wall-clock is whole-second resolution from the shell; expect a few percent
  run-to-run variance, especially for the link-bound warm rebuild.
- Numbers are machine-specific. Always compare a before/after **pair captured on
  the same machine** — never an absolute number against a different host.
- The third-party registry cache (`~/.cargo`) is shared, so the cold build
  measures compile + link time, not crate download time.

## Recorded baseline

<!-- AAASM-2573: measured numbers are recorded in the measurement commit. -->

## Acceptance-criteria mapping (AAASM-2557)

| Acceptance criterion | Evidence |
|---|---|
| Baseline numbers for cold build, warm rebuild, and test build+run recorded | "Recorded baseline" → wall-clock table |
| `cargo build --timings` HTML identifies the top 5 longest-compiling crates | "Recorded baseline" → top-crates table (`target/build-baseline/cargo-timing.html`) |
| `cargo tree -d` attached as the dedup baseline for AAASM-2555 | "Recorded baseline" → duplicate-dependency table (`target/build-baseline/cargo-tree-dups.txt`) |
