# AAASM-2601 — Verification: relocate acceptance-cost CI jobs

Verifies Story **AAASM-2601** (move coverage/Sonar off the PR hot-path; gate
benchmark behind a label). Implementation in subtask **AAASM-2612** (PR #948);
this subtask (**AAASM-2613**) checks it against the Story acceptance criteria.

## Context

`master` has **no required status checks** (branch protection = review-required
only; `gh api …/required_status_checks` → 404 "not enabled"). So gating these jobs
to skip on routine PRs does **not** wedge merges — no branch-protection change needed.

## How verified

| # | Method |
|---|--------|
| 1 | Read the three job `if:` conditions in `ci.yml` after the change. |
| 2 | Confirmed the disk-space guard step is retained in `coverage`. |
| 3 | `yaml.safe_load` parse of `ci.yml`. |
| 4 | Observed PR #948's own run (unlabelled) — `Coverage` / `SonarCloud analysis` / `Benchmark` report **skipped**. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `coverage`/`sonar`/`benchmark` no longer run on an unlabelled routine PR | ✅ Pass | `coverage` & `sonar` `if:` → `… && (github.event_name == 'push' \|\| contains(github.event.pull_request.labels.*.name, 'run-coverage'))`; `benchmark` → `… 'run-benchmark'`. PR #948 (unlabelled) shows all three **skipped**. |
| They still run on `push: master` and on labelled PRs | ✅ Pass | `github.event_name == 'push'` covers the post-merge master trend; the `run-coverage` / `run-benchmark` labels cover on-demand PRs. |
| Disk-space guard retained on the instrumented build | ✅ Pass | `coverage`'s "Free disk space (reclaim runner space for llvm-cov build)" step is unchanged. |
| YAML valid | ✅ Pass | `yaml.safe_load` clean. |

## Outcome

- All ACs **pass**. Coverage trend (master) and on-demand diff-coverage (label) preserved;
  routine PRs no longer pay the llvm-cov instrumented build, the SonarCloud scan, or the
  noisy benchmark.
- No gaps found; nothing filed back to AAASM-2612.
