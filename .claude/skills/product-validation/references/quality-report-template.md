# references/quality-report-template.md — product-validation

## Why this exists, and why it's mandatory even with zero defects

The quality report is the durable, discoverable record that
product-level QA actually happened and what it found — including when it
found nothing. **Produce it every time this skill runs, even when zero
Bugs were filed.** A validation pass that found no defects is a
legitimate, valuable PASS result; it is not evidence the report step can
be skipped. The absence of a report is indistinguishable from "QA never
ran" to anyone reading the repo later — silence is not proof of quality.

Raw evidence (logs, screenshots, video, full command output) stays in
bounded, disposable CI/test artifacts — it is allowed to be large,
temporary, and CI-retention-bounded. **The quality report itself is the
durable, discoverable truth** — checked into the repo (or otherwise
durably filed, e.g. attached to the release/Story in Jira), small enough
to read in one sitting, and linking to the raw evidence rather than
inlining all of it.

## Template

```markdown
# Quality Report — <product> <version-or-campaign>

## Header
- Product:
- Version / commit tested:
- Environment(s): (OS, runtime versions, deployment shape)
- Date:
- Evaluator(s) / independence tier: (see validation-tracks.md's
  fresh-context/independence principle — state which tier was used)

## Scenarios executed
| scenario_id | track | persona | outcome | evidence link |
|---|---|---|---|---|
| ... | smoke / golden-journey / adversarial / docs-driven | ... | PASS / FAIL / BLOCKED / NOT_APPLICABLE | ... |

Outcome definitions:
- **PASS** — ran to completion, expected outcome met.
- **FAIL** — ran to completion, expected outcome not met; must have a
  linked Jira Bug (see defect-lifecycle.md) unless judged non-material,
  in which case state why here.
- **BLOCKED** — could not run to completion for a reason outside the
  scenario itself (missing environment, unresolved dependency); state
  the blocker and whether it's itself worth a Bug.
- **NOT_APPLICABLE** — track doesn't apply to this product/surface (e.g.
  a track requiring a rendered UI, on a pure CLI). State why; this is a
  truthful outcome, not a gap to apologize for.

## Defects
| Jira key | severity | scenario | status | rerun result |
|---|---|---|---|---|
| ... | Critical/High/Medium/Low | ... | fixed / deferred / accepted-known-limitation | PASS / N/A |

## Known limitations
Defects deliberately not fixed this pass, each with its rationale
(deferred or accepted — see defect-lifecycle.md). Do not use this
section for defects that were simply never filed.

## Functional / usability assessment
Narrative: does the product actually do what it claims, and is it usable
by the persona(s) tested — beyond the pass/fail table. This is where
friction that isn't a filed Bug (e.g. "worked but was confusing") gets
recorded honestly.

## Design QA verdict (when applicable)
State the `design-qa` skill's verdict if that skill was composed in
(material rendered UI/UX surface) — or state NOT_APPLICABLE with why if
this product has no rendered surface (see product-validation's SKILL.md
composition section).

## Documentation-driven journey result (when applicable)
State the Track 4 result if run — PASS/FAIL/BLOCKED — and whether any
docs-content gap was found (route the content fix through
`documentation-experience`; the underlying defect still follows this
skill's defect lifecycle if it's a product behavior gap, not only a
wording gap).

## Final recommendation
One of: READY / READY WITH KNOWN LIMITATIONS / NOT READY — plus the one-
or-two-sentence reasoning a reader needs without re-reading the whole
report.
```

## Recommended fallback repo structure

Use this when a repo has no stronger existing QA convention of its own.
**A repo's own existing stronger QA convention wins** — do not force this
structure onto a repo that already has a working, more specific one (see
"repo's own existing" precedent below).

```
qa/
  scenarios/         # one file per scenario, canonical scenario schema
  reports/<version-or-campaign>/   # quality reports, one per release/campaign
  fixtures/          # deterministic, fake test data — never real user/customer data
  runners/           # scripts that execute scenarios and produce report input
```

This is a fallback, not a mandate — real Horonom repos already use
several different, equally legitimate shapes for the same underlying
content and none of them should be forced to rename into `qa/scenarios/`
retroactively:

- `eltanin/docs/qa/feature-verification/` — one Feature Verification
  Record per Feature (e.g. `F-M1-003.md`), following the format
  established ahead of a formal template, explicitly noting it may be
  restructured later without its *content* needing to change. This is
  functionally a `qa/reports/` equivalent, scoped per-Feature rather than
  per-release.
- `circinus/docs/hardening/HORO-<n>-fresh-user-dogfood-report.md` and
  `circinus/docs/validation/` — dogfood/validation campaign reports filed
  by ticket, not under a `qa/` directory at all.
- `ophiuchus/docs/dogfood-tester-guide.md` — a combined
  runner-instructions-plus-measurement-template document, playing the
  role `qa/runners/` + a scenario template would play, as one file.

When a repo has none of the above and no stronger convention of its own,
default to the `qa/scenarios/` / `qa/reports/` / `qa/fixtures/` /
`qa/runners/` shape above rather than inventing a fifth variant.
