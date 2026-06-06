# AAASM-2598 — Verification: CI concurrency cancels superseded PR runs

Verifies Story **AAASM-2598** (add `concurrency` to all PR-triggered workflows).
Implementation in subtask **AAASM-2602** (PR #942); this subtask (**AAASM-2603**)
checks it against the Story acceptance criteria.

## How verified

| # | Method |
|---|--------|
| 1 | Static: each PR-triggered workflow `.yml` parsed with `yaml.safe_load`; confirmed a top-level `concurrency` mapping with `group` + `cancel-in-progress`. |
| 2 | Confirmed `release.yml` has **no** `concurrency` block (tag-only, must never cancel) and `smoke-test.yml` is unchanged (already had one). |
| 3 | Behavioural (post-merge): push a 2nd commit to an open PR and confirm the 1st run is cancelled for each workflow; confirm a `master`/tag run is never cancelled. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| All 7 PR-triggered workflows have the `concurrency` block | ✅ Pass | `ci.yml`, `docker.yml`, `ffi-go-staticlib.yml`, `integration-tests.yml`, `integration-bypass-permissions.yml`, `dev-verify.yml`, `docs.yml` — all parse with `concurrency.group = "${{ github.workflow }}-${{ github.ref }}"` |
| `cancel-in-progress` gated to `pull_request` | ✅ Pass | Every block: `cancel-in-progress: ${{ github.event_name == 'pull_request' }}` → `master`/tag runs never cancel |
| `release.yml` untouched; `smoke-test.yml` unchanged | ✅ Pass | `release.yml` has no `concurrency`; `smoke-test.yml` diff is empty |
| No workflow YAML parse error | ✅ Pass | All 7 load cleanly; CI (`Build mdBook` / workflow registration) green on PR #942 |
| Superseded PR run is cancelled (behavioural) | ⏳ Post-merge | To observe after merge: a 2nd push to any open PR cancels the prior run of each workflow. Documented here as the acceptance step; structural change is in place. |

## Outcome

- Structural ACs: **pass**. The behavioural cancellation is a property of the merged
  `concurrency` config and is confirmed on the first post-merge PR that receives a
  second push.
- No gaps found; nothing filed back to AAASM-2602.
