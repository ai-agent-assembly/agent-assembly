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

Captured **2026-06-05** on Apple M-series (arm64, 16 logical CPUs, 128 GB),
macOS Darwin 25.4.0, `cargo 1.95.0`, `cargo-nextest 0.9.133`, default
`[profile.dev]` and `[profile.release]` (i.e. the pre-Epic configuration).

| Measurement | Wall-clock |
|---|---|
| Cold build (`cargo build --workspace --timings`) | **124 s** |
| Warm rebuild (touch `aa-cli/src/main.rs`, relink) | **5 s** |
| Test build (`cargo nextest run --workspace --no-run`) | **396 s** |
| Packages built in >1 version (`cargo tree -d`) | **34** |
| Distinct duplicate `(name, version)` build units | **105** |

> Local wall-clock is noisy: across three runs the cold build measured
> 91–211 s on this machine (background load / thermal). Treat these as the
> local order-of-magnitude; the Epic's per-Story before/after pairs must be
> captured on the same idle machine, and CI numbers are authoritative.

### Top longest-compiling crates

From the archived `cargo build --timings` HTML
(`target/build-baseline/cargo-timing.html`), summing each crate's units
(build-script + lib + codegen):

| Rank | Compile (s) | Crate |
|---|---|---|
| 1 | 63.6 | `aws-lc-sys` 0.40.0 |
| 2 | 35.2 | `wasmtime` 45.0.0 |
| 3 | 33.7 | `cranelift-codegen` 0.132.0 |
| 4 | 29.8 | `rustls` 0.23.40 |
| 5 | 25.3 | `object` 0.39.1 |
| 6 | 25.2 | `libsqlite3-sys` 0.30.1 |
| 7 | 23.1 | `asn1-rs` 0.7.1 |
| 8 | 22.9 | `thiserror` 1.0.69 |
| 9 | 21.0 | `rustix` 1.1.4 |
| 10 | 21.0 | `wasmtime-internal-jit-debug` 45.0.0 |

The long poles are the **WebAssembly** stack (`wasmtime`, `cranelift-codegen`,
`wasmtime-internal-jit-debug` — pulled by `aa-wasm`) and **crypto/TLS**
(`aws-lc-sys`, `rustls`), confirming the Epic's hypothesis. Per-crate seconds
shift run-to-run with build parallelism, but this set is stable.

### Duplicate dependencies (dedup baseline for AAASM-2555)

`cargo tree -d` reports **34 packages built in more than one version**
(105 distinct `(name, version)` units). The worst offenders:

| Versions | Package |
|---|---|
| 4 | `hashbrown` |
| 3 | `rand`, `rand_core`, `getrandom` |
| 2 | `winnow`, `webpki-roots`, `wast`, `wasm-encoder`, `untrusted`, `toml`, `toml_datetime`, `thiserror-impl`, … |

The complete set of multi-version packages — the committed dedup baseline for
AAASM-2555 to diff against — follows. The full `cargo tree -d` report (with the
inverted dependent trees) is also archived at
`target/build-baseline/cargo-tree-dups.txt` for the dependency paths.

```text
block-buffer        v0.10.4  v0.12.0
const-oid           v0.9.6   v0.10.2
convert_case        v0.10.0  v0.11.0
cpufeatures         v0.2.17  v0.3.0
crypto-common       v0.1.7   v0.2.1
deadpool            v0.12.3  v0.13.0
deadpool-runtime    v0.1.4   v0.3.1
digest              v0.10.7  v0.11.3
fixedbitset         v0.4.2   v0.5.7
foldhash            v0.1.5   v0.2.0
getrandom           v0.2.17  v0.3.4   v0.4.2
hashbrown           v0.14.5  v0.15.5  v0.16.1  v0.17.1
hashlink            v0.9.1   v0.10.0
hmac                v0.12.1  v0.13.0
itertools           v0.13.0  v0.14.0
lru                 v0.16.4  v0.18.0
petgraph            v0.6.5   v0.8.3
phf                 v0.11.3  v0.12.1
phf_shared          v0.11.3  v0.12.1
rand                v0.8.6   v0.9.4   v0.10.1
rand_chacha         v0.3.1   v0.9.0
rand_core           v0.6.4   v0.9.5   v0.10.1
reqwest             v0.12.28 v0.13.3
sha2                v0.10.9  v0.11.0
similar             v2.7.0   v3.1.1
thiserror           v1.0.69  v2.0.18
thiserror-impl      v1.0.69  v2.0.18
toml                v0.9.12  v1.1.2
toml_datetime       v0.7.5   v1.1.1
untrusted           v0.7.1   v0.9.0
wasm-encoder        v0.248.0 v0.251.0
wast                v35.0.2  v251.0.0
webpki-roots        v0.26.11 v1.0.7
winnow              v0.7.15  v1.0.2
```

AAASM-2555 should re-run `cargo tree -d` after centralizing
`[workspace.dependencies]` and confirm this count drops.

### Full test build+run (context)

The default harness records test **compile** time only, because the full
suite's run wall-clock is dominated by integration-test execution rather than
the build. For reference, one `BUILD_BASELINE_RUN_TESTS=1` capture on the same
machine measured **3452 s** end-to-end build+run — of which the run phase was
`Summary [2546 s] 3764 tests run: 3744 passed (228 slow, 4 leaky), 20 failed`.
The 20 failures are local timing-sensitive integration assertions (e.g. the
`aa-api` L1-invalidation 100 ms check) and do not affect compile time. This
number is here for completeness; the profile/linker/dedup Stories should be
judged against the **compile** rows above, not this run-dominated figure.

## Acceptance-criteria mapping (AAASM-2557)

| Acceptance criterion | Evidence |
|---|---|
| Baseline numbers for cold build, warm rebuild, and test build+run recorded | "Recorded baseline" → wall-clock table (cold/warm/test-build) + "Full test build+run (context)" |
| `cargo build --timings` HTML identifies the top 5 longest-compiling crates | "Top longest-compiling crates" table (`target/build-baseline/cargo-timing.html`) |
| `cargo tree -d` attached as the dedup baseline for AAASM-2555 | "Duplicate dependencies" table (`target/build-baseline/cargo-tree-dups.txt`) |
