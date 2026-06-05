# AAASM-2628 — Verification: ci.yml schemas/openapi trigger-path fix

Verifies Story **AAASM-2628** (close the `ci.yml` trigger gap where schemas-only
changes never started CI). Implementation in subtask **AAASM-2629** (PR #959);
this subtask (**AAASM-2630**) checks it against the Story acceptance criteria.

## Background

The gap was found during the AAASM-2599 post-merge workflow audit: `ci.yml`'s
top-level `on.push.paths` / `on.pull_request.paths` listed only `openapi/v1.yaml`
and omitted `schemas/**`. Because GitHub evaluates the workflow-level `paths`
*before* any job runs, a PR touching only `schemas/**` never started `ci.yml`,
so `schema-lint` (ajv validation of `schemas/policy/v1/policy-document.schema.json`
and the three example policies) never ran on it. The AAASM-2599 `changes` router
already had `schema`/`openapi` outputs, but a job-level filter cannot help if the
workflow is never triggered.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load(ci.yml)` — parses clean. |
| 2 | Asserted both `on.push.paths` and `on.pull_request.paths` now contain `schemas/**` and `openapi/**`, and no longer the narrow `openapi/v1.yaml`. |
| 3 | Asserted the two single-quoted `changes`-job filter refs to `'openapi/v1.yaml'` are unchanged (the fix touches only the trigger blocks). |
| 4 | Path-match reasoning: `schemas/policy/v1/policy-document.schema.json` and `schemas/examples/*.yaml` match `schemas/**`; the workflow now triggers and the `changes` `schema` filter (`schemas/**`) sets `schema=true` → `schema-lint` runs. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| A schemas-only PR triggers `ci.yml` and runs `schema-lint` | ✅ Pass | `schemas/**` added to both trigger path lists; `schema` router output already gates `schema-lint`. |
| An openapi-only PR triggers `ci.yml` and runs the OpenAPI jobs | ✅ Pass | `openapi/v1.yaml` broadened to `openapi/**` in both trigger lists; `openapi` output gates `openapi-drift`/`openapi-lint`. |
| No change to which jobs run for existing code PRs | ✅ Pass | Additions only broaden the trigger surface; `openapi/v1.yaml ⊂ openapi/**`, so every previously-triggering change still triggers. No filter or `if:` gate changed. |
| `ci.yml` remains YAML-valid | ✅ Pass | `yaml.safe_load` clean. |

## Outcome

- All ACs **pass**. The fix is purely additive to the trigger surface — it can
  only cause CI to run on *more* changes, never fewer, so there is no regression
  risk to existing routing.
- Closes the audit finding recorded on AAASM-2599. No further gaps found in the
  trigger-path layer: every `changes`-router area filter now has a matching (or
  superset) entry in the workflow-level `paths`.
