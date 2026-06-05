# AAASM-2599 — Verification: fine-grained `ci.yml` router + aggregate gate

Verifies Story **AAASM-2599** (per-area path router + single `CI Success` gate).
Implementation in subtask **AAASM-2621** (PR #952); this subtask (**AAASM-2622**)
checks it against the Story acceptance criteria.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load` of `ci.yml` after every edit — parses clean. |
| 2 | Asserted the 4 new outputs (`proto`/`schema`/`openapi`/`storage`) resolve to `steps.filter.outputs.*` and each filter's paths are a **strict subset** of the broad `rust` filter (so re-gating cannot lose coverage). |
| 3 | Asserted the six re-gated jobs now reference their area output (`buf-lint→proto`, `schema-lint→schema`, `openapi-drift`/`openapi-lint→openapi`, `timescaledb-tests`/`migration-drift-check→storage`). |
| 4 | Asserted `ci-success.needs` = every job **except** `ci-success`, `coverage`, `sonar` (28 needs / 31 jobs) and that the gate logic fails on `failure`/`cancelled`, tolerates `skipped`. |

## Scope decision (documented deviation — not a silent downscope)

The Story sketched a more aggressive routing: a new `core` output that **excludes**
`aa-ebpf*`/`aa-proto`/`aa-ffi-go` from the always-on `build/fmt/clippy/test/deny/no-std`
gate, plus a `conformance` output for the conformance jobs.

Implementation kept the **always-on Rust gate and the conformance jobs on the broad
`rust` output** and added only the four *additive, strict-subset* narrow outputs.
Rationale: `aa-ebpf*` host code and `aa-proto` are workspace members compiled and
tested by `cargo nextest --workspace`; excluding them from the core gate would skip
their unit-test coverage on an ebpf-/proto-only PR (the `ebpf-build` job builds the
probes + integration but does not run the host crates' unit suite). That trades a
real coverage guarantee for a marginal saving and conflicts with the Story's own
AC-5 ("no regression in coverage of what actually runs"). The narrow validators that
*do* have a closed input set (proto lint, schema lint, openapi drift/lint, storage
testcontainer tests) were narrowed — that is where the real, safe saving is. The
`core`-exclusion variant remains available as a follow-up if the team later confirms
ebpf/proto host crates are non-members or otherwise independently covered.

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Changing only `aa-core` triggers core jobs but **not** ebpf/proto/openapi/schema/timescaledb jobs | ✅ Pass | `aa-core/**` ∈ `rust` only → `rust=true`; `ebpf`/`proto`/`schema`/`openapi`/`storage` all `false` → those jobs skip. (Conformance also runs — see below.) |
| …**not** conformance | ⚠️ Adapted | Conformance jobs stay on `rust` by design — they exercise the Rust impl, so they must run on any core change. Documented above; AC-5 takes precedence. |
| A `proto/**` change triggers `buf-lint` **and** conformance | ✅ Pass | `proto/**` ∈ both `proto` (→ buf-lint) and `rust` (→ conformance). |
| An `aa-ebpf*` change triggers the eBPF jobs | ✅ Pass | `aa-ebpf*/**` ∈ `ebpf` → `ebpf-build`/`e2e-ebpf-linux` run (unchanged from AAASM-2580). |
| An `aa-api`/`openapi` change triggers the OpenAPI jobs | ✅ Pass | `aa-api/**`,`openapi/**` ∈ `openapi` → `openapi-drift`/`openapi-lint` run. |
| `CI Success` green when relevant jobs pass and the rest skip; red if any relevant job fails/cancelled | ✅ Pass | `if: always()` + `for r in ${{ join(needs.*.result,' ') }}; case failure\|cancelled) exit 1`. `skipped`/`success` pass. |
| Branch protection requires only `CI Success`; a PR with legitimately-skipped jobs is mergeable | ✅ Pass (mechanism) | Gate added and is the single status designed to be required. `master` currently has **no** required checks, so skips wedge nothing today; enabling the requirement is a one-line admin toggle (no code dependency). |
| No regression in coverage of what actually runs | ✅ Pass | Always-on gate (`build/fmt/clippy/docs/test/deny/no-std/conformance*`) runs on every code PR; the four narrow filters are strict subsets of `rust`. `coverage`/`sonar` stay advisory (excluded from the gate). |
| All workflows YAML-valid | ✅ Pass | `yaml.safe_load(ci.yml)` clean after each commit. |

## Outcome

- All ACs **pass** except the conformance-skip sub-point, which was **deliberately
  adapted** to honour AC-5's no-coverage-regression requirement (documented above,
  not silently dropped).
- Net effect: an `aa-cli`-only PR now skips `buf-lint`, `schema-lint`, `openapi-*`
  and the two slow Postgres testcontainer jobs; a single `CI Success` status now
  represents merge-readiness regardless of which areas a PR touches.
- No bugs found; nothing filed back to AAASM-2621. The `core`/ebpf-exclusion variant
  is recorded as an optional future refinement, not a gap.
