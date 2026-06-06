# CI/CD Pipeline Performance

Before/after record of the **CI/CD workflow redesign** delivered under **Epic
AAASM-2551** (_Rust build & compile-time performance — local + CI_). This page
documents **what changed and why**, and quotes **real GitHub Actions run data**
proving the speed-up.

> This is distinct from [Build-Time Baseline](build-time-baseline.md), which
> measures how long the workspace takes to **compile**. This page measures how
> long the **CI pipeline** takes end-to-end per change, and how much runner
> compute it consumes.

## The problem (before)

`ci.yml` had ~30 jobs gated by a **binary** `changes` router (`dorny/paths-filter`
emitting only `rust` / `dashboard` / `ebpf`). Any edit under `aa-*/**` set
`rust == true`, which fanned out to **~22 Rust jobs regardless of which sub-area
changed** — including the expensive ones that are almost never relevant to a
given change: the eBPF nightly build + sudo e2e, the proto breaking-check, the
OpenAPI drift + Spectral lint, the schema lint, the TimescaleDB and
migration-drift testcontainer jobs, full `llvm-cov` coverage, SonarCloud, and the
criterion benchmark. There was also **no aggregate gate job**, and the
`aa-integration-tests` suite ran twice on Linux.

The result: a one-line dependency bump paid for nearly the entire matrix.

## What changed

| Story | Change |
|---|---|
| **AAASM-2598** | Per-workflow `concurrency` groups; `cancel-in-progress` gated to `pull_request` (superseded PR runs are cancelled; pushes/releases never are). |
| **AAASM-2599** | Fine-grained `changes` router — added `proto` / `schema` / `openapi` / `storage` outputs (each a strict subset of `rust`) and re-gated the single-purpose validators onto them. Added a single **`CI Success`** aggregate gate (`needs` every functional job, `if: always()`, fails on any `failure`/`cancelled`; `coverage`/`sonar` excluded as advisory). |
| **AAASM-2600** | Docker / FFI images build PR-light (one arch, `is_latest` only) on PRs; full multi-arch + push only on `v*` tags. |
| **AAASM-2601** | Relocated `Coverage` / `SonarCloud` / `Benchmark` behind `push`-or-label gates — they no longer run on every PR. |
| **AAASM-2611** | Least-privilege `permissions: contents: read` at the top of every workflow; write elevated per-job only where needed. |
| **AAASM-2628** | Closed a trigger-path gap — `schemas/**` (and `openapi/**`) were missing from `ci.yml`'s `on.*.paths`, so schema-only changes never ran `schema-lint`. |
| **AAASM-2631** | Dropped the redundant Linux `aa-integration-tests` run — it already runs in `ci.yml`'s `test` job; the dedicated workflow is now macOS-only. |

The mechanism: a typical change now runs the **always-on fast gate**
(`build`, `fmt`, `clippy`, `rustdoc`, `test`, `deny`, `no-std`, conformance) **plus
only the area(s) it actually touched**. Everything else skips, and a single
`CI Success` status summarises the run.

## Measured results (real GitHub Actions runs)

### Apples-to-apples: the identical dependency-bump PR, before and after

The same `dependabot/cargo/master/async-nats-0.49.1` PR was re-run before and
after the redesign — same diff, same content:

| Metric | Before — run #2179 (2026-06-04) | After — run #2283 (2026-06-06) | Δ |
|---|---|---|---|
| Jobs executed | **23** of 30 | **16** of 32 | −7 jobs |
| Runner-minutes (Σ job durations) | **64.0** | **17.3** | **−73 %** |
| Wall-clock | **71.1 min** | **10.0 min** | **−86 % (7.1× faster)** |

Because `async-nats` is a transitive cargo bump that touches no proto / schema /
OpenAPI / storage / eBPF / dashboard code, the after-run correctly **skips**
`Benchmark`, `Coverage`, `SonarCloud`, `Migration drift check`, `TimescaleDB
Tests`, `Proto lint & breaking check (buf)`, `Schema lint`, `OpenAPI drift`,
`OpenAPI lint`, and both eBPF jobs — none of which it can affect.

### Dashboard-only PR

A dashboard dependency bump now runs **only the dashboard jobs**:

| | Before — run #2180 | After — run #2288 |
|---|---|---|
| Jobs executed | full dashboard + rust fan-out | **7** of 31 (24 skipped — every Rust job) |
| Wall-clock | **55.2 min** | **10.4 min** |

### Master push (full coverage, incl. `Coverage` + `SonarCloud`)

Pushes still run the acceptance jobs (`Coverage`/`Sonar` are `push`-gated), yet
still benefit from area-routing, concurrency cancellation, and the shared
dashboard-assets artifact:

| | Before — run #2200 | After — run #2292 |
|---|---|---|
| Runner-minutes | **80.8** | **44.1** | 
| Wall-clock | **132 min** | **29 min** |

## Methodology & caveats

- Data was pulled from the GitHub Actions REST API
  (`/repos/.../actions/runs/<id>/jobs`). **Runner-minutes** = the sum of each
  non-skipped job's `completed_at − started_at`. **Wall-clock** = the run's
  `updated_at − run_started_at`.
- **Runner-minutes and job-count are deterministic** measures of work performed.
  **Wall-clock carries cache-warmth and runner-availability noise** (a cold
  `Swatinem/rust-cache` or a busy runner pool inflates it), so treat the
  wall-clock figures as illustrative and the runner-minute / job-count figures as
  the load-bearing evidence.
- Run numbers are cited so each row can be re-inspected:
  `gh api repos/AI-agent-assembly/agent-assembly/actions/runs/<id>/jobs`.

## Takeaway

For the common case — a focused change or a dependency bump — the pipeline does
**~75 % less work** and returns a result **~7× sooner**, while a single
`CI Success` gate still guarantees nothing necessary was skipped: every functional
job is a dependency of the gate, and each area's validators run whenever their own
inputs change.
