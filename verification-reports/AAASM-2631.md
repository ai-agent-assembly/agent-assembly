# AAASM-2631 — Verification: integration-tests macOS-only

Verifies Story **AAASM-2631** (drop the redundant Linux `aa-integration-tests`
run). Implementation in subtask **AAASM-2632** (PR #961); this subtask
(**AAASM-2633**) checks it against the Story acceptance criteria.

## Background

`aa-integration-tests` ran twice on Linux per PR: once parallel in `ci.yml`'s
`test` job (`cargo nextest run --workspace …` includes the crate) and once
serially in `integration-tests.yml` on `ubuntu-latest`. The tests bind ephemeral
ports (`TcpListener::bind("127.0.0.1:0")`) and already pass concurrently in
`test`, so the serial Linux run was pure duplication. The fix drops the
`ubuntu-latest` matrix leg; macOS remains the workflow's unique coverage.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load(integration-tests.yml)` — parses clean. |
| 2 | Asserted `jobs.integration-tests.strategy.matrix.os == ['macos-latest']`. |
| 3 | Asserted no step retains `if: matrix.os == 'ubuntu-latest'` (the dead Linux protoc step was removed; the macOS protoc step's now-redundant `if` was dropped). |
| 4 | Confirmed on master that `ci.yml`'s `test` job still runs `cargo nextest run --workspace --no-tests=pass --exclude aa-ebpf` — **no `--exclude aa-integration-tests`** — so the crate still executes on `ubuntu-latest` for every `rust` PR. |
| 5 | Trigger surfaces: `ci.yml` `test` is gated on `rust` (superset of `integration-tests.yml`'s `aa-api`/`aa-gateway`/`aa-cli`/`aa-runtime`/`aa-integration-tests` paths), so Linux integration coverage is at least as broad as before. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `integration-tests.yml` runs only on `macos-latest` | ✅ Pass | matrix `os: [macos-latest]`. |
| Linux integration coverage preserved by `ci.yml` `test` | ✅ Pass | `test` runs `--workspace` (incl. `aa-integration-tests`) on `ubuntu-latest`; no `--exclude` added; broader `rust` trigger. |
| macOS integration coverage unchanged | ✅ Pass | Same trigger paths, same `cargo nextest run -p aa-integration-tests --test-threads=1` on macOS. |
| YAML valid; no orphaned `ubuntu-latest` steps | ✅ Pass | `yaml.safe_load` clean; no `if: matrix.os == 'ubuntu-latest'` remains. |

## Outcome

- All ACs **pass**. The redundant Linux run is removed with **zero coverage
  loss**: Linux integration testing is retained (and actually broadened) by
  `ci.yml`'s `test` job, macOS retained by this workflow.
- Net effect per affected PR: one fewer Linux integration run (the slow serial
  ~20-min job), no change to what is actually tested.
- Closes the last finding from the CI/CD workflow audit. No further duplication
  found across the 9 workflows.
