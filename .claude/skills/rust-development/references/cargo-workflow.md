# Reference — Cargo/nextest/clippy workflow

Concrete commands `rust-development`'s SKILL.md routes to for each
`engineering-loop` stage. This reference owns the commands; it does not
redefine the execution model or diagnostic contract those belong to
`engineering-loop` (`agents/skills/engineering-loop/SKILL.md` and its
`agents/skills/engineering-loop/references/diagnostic-contract.md`).

## Repository/workspace discovery

Before running anything, establish shape:

- `cargo metadata --no-deps --format-version 1` (or a quick read of the
  root `Cargo.toml`'s `[workspace]` table) to confirm whether this is a
  single crate or a multi-member workspace, and which members exist.
- A workspace commonly has one `Cargo.lock` at the root and per-member
  `Cargo.toml` files — never assume a nested crate has its own lockfile.
- Check `.cargo/config.toml` (repo-local) for build/linker/target-dir
  overrides already in effect before layering your own flags on top —
  don't fight a setting the repo already made deliberately.
- Identify the repo's own authoritative CI/full-gate command (its CI
  workflow file, `CONTRIBUTING.md`, or a `Makefile`/`justfile` target) —
  that command, not an invented one, is what Full Gate runs.

## `cargo check` vs. build/link/native boundary

`cargo check` type-checks and borrow-checks without codegen or linking.
It is the fastest Narrow-stage signal, and it is also structurally unable
to prove several classes of correctness:

| `cargo check` cannot catch | Because |
|---|---|
| Linker errors, missing symbols | No linking is performed |
| FFI/native symbol-resolution failures | No native codegen or linking |
| `build.rs` output/codegen problems that only surface at build time | Build scripts may run, but their downstream codegen effects aren't fully exercised the way a real build does |
| `#[cfg]`-gated code paths not covered by the checked feature set | Only checks the active target/feature configuration |
| Release-profile-only breakage (LTO, `codegen-units=1`, `panic=abort` interactions) | Those profiles are never invoked by `check` |

Use `cargo check` (or `cargo check -p <crate>`) freely during the edit
loop for fast type feedback. Never report it as "the build passes" or
"the change is verified" — that claim requires an actual `cargo build`
(for link/native proof) and the repo's Full Gate (for release-profile and
full-workspace proof).

## Targeted test loops

Scope every test invocation during iteration — this is the single
highest-leverage habit in this reference, not a style preference. An
unscoped `cargo nextest run` (or `-p <crate>` with no further narrowing)
discovers and links every test target in scope before applying any
filter, which costs real, disproportionate wall time as target count
grows, independent of how fast the actual test body runs. See
`references/aa-evidence-classification.md` bucket (a) for the underlying
mechanism this generalizes from.

Preferred forms, narrowest first:

```
cargo nextest run -p <crate> <module>::<test_name>   # one test
cargo nextest run -p <crate> --lib                   # one crate's lib target
cargo nextest run -p <crate> --test <test_file_stem> # one integration-test binary
cargo nextest run -p <crate>                         # whole crate, all its targets
```

Plain `cargo test` supports the same `-p`/`--lib`/`--test <stem>`
narrowing if `cargo-nextest` isn't installed — treat nextest as the
preferred accelerator and `cargo test` as its native fallback, per the
same preferred→fallback shape documented in
`agents/skills/engineering-loop/references/optional-tool-fallback.md`.

Reserve an unscoped `--workspace` (or no-package-filter) test run for the
Full Gate stage, where discovering and running everything is the actual
point, not overhead to route around.

## Clippy, rustfmt, and doc validation

- `cargo clippy -p <crate> --all-targets --all-features -- -D warnings`
  scoped the same way as tests during iteration; drop the package filter
  for the Full Gate lint pass, matching the repo's own CI invocation
  (check for feature-flag variants CI runs that a local scoped pass
  might miss).
- `cargo fmt --check` (or `cargo fmt -p <crate> --check`) before treating
  formatting as settled — never hand-format to match `rustfmt`'s output.
- `cargo doc -p <crate> --no-deps` surfaces broken intra-doc links and
  doctest-adjacent issues; `cargo test --doc -p <crate>` actually runs
  doctests, which `cargo check`/`clippy` do not exercise.

## High-signal diagnostics

When a check fails, read the actual diagnostic before escalating through
`engineering-loop`'s L0→L3 ladder:

- rustc/clippy diagnostics carry file:line, an error code (`E0308`, etc.),
  and frequently a suggested fix (`help: consider ...`) — that suggestion
  is a starting hypothesis, not an instruction to apply blindly.
- A linker error (`undefined symbols for architecture ...`,
  `cannot find -l<name>`) means the check/build boundary above was
  crossed — this is exactly the class of failure `cargo check` cannot
  have caught earlier, so don't be surprised it only appears at `build`.
- nextest failure output separates "test panicked" (assertion output,
  the useful part) from harness/build noise — don't summarize a run by
  its wall time alone; report which specific test(s) failed and why.
- If a long-running Cargo/nextest command looks stalled, check for live
  `cargo`/`rustc`/`nextest`/linker child processes and target-artifact
  mtime changes before concluding it's hung — some discovery/link phases
  are legitimately slow rather than stuck (see
  `references/aa-evidence-classification.md` for the evidence this
  generalizes, and note its confirmed-vs-inferred caveat).
