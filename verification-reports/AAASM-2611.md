# AAASM-2611 — Verification: CI hardening

Verifies Story **AAASM-2611** (least-privilege permissions + trigger/concurrency
consistency). Implementation in subtask **AAASM-2615** (PR #950); this subtask
(**AAASM-2616**) checks it against the Story acceptance criteria.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load` of all 9 workflows; inspected top-level `permissions` of each. |
| 2 | Confirmed write jobs retain/gain explicit per-job permissions (audit before clamping). |
| 3 | Confirmed `docs.yml` PR `branches` and `release.yml` `concurrency`. |
| 4 | CI green on PR #950 (every running job succeeded under `contents: read` → nothing lost a needed permission). |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Every workflow declares top-level `permissions:`; write jobs explicitly elevated | ✅ Pass | All 9 have a top-level block (8 × `contents: read`; `smoke-test` keeps `contents: read, issues: write, packages: read`). Per-job write retained: `docker` build → `packages: write`; `release` `publish`/`update-homebrew-tap`/`notify-downstream` → existing per-job; **`release-status-aggregator` → added `contents: write`** (its `gh release edit`). |
| `ci.yml` clamp is safe | ✅ Pass | Both tokens read-only (buf-setup auth; Sonar scanner reads PR context). CI green on #950. |
| `docs.yml` PR trigger scoped to master | ✅ Pass | `pull_request.branches: [master]` added. |
| `release.yml` has a `concurrency` block | ✅ Pass | `group: release-${{ github.ref }}`, `cancel-in-progress: false`. |
| All workflows YAML-valid | ✅ Pass | `yaml.safe_load` clean on all 9. |
| release permission change is tag-only | ✅ Pass (by construction) | `release.yml` runs only on `v*` tags; exercised at the next release. The aggregator's added `contents: write` preserves its `gh release edit`. |

## Outcome

- All ACs **pass**. The `GITHUB_TOKEN` blast radius is now least-privilege per workflow
  without removing any permission a job actually uses (CI green on #950 confirms for the
  PR-exercised workflows; `release.yml` verified by construction).
- B2 (sonar `if`) was folded into AAASM-2601. No gaps found; nothing filed back to AAASM-2615.
