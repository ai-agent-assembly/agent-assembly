# QA sign-off — v<version>

> Per-release QA-verification sign-off artifact. Produced by the
> [`/release-qa-gate`](../../../.claude/skills/release-qa-gate/SKILL.md) SKILL
> and enforced by `scripts/release-readiness.sh` (the readiness run fails unless
> this file exists for `<version>` and contains `Verdict: PASS`).
>
> This artifact is **independent of, and additive to,** the
> [security sign-off](../security-signoff/TEMPLATE.md) — a `Verdict: PASS` here
> never overrides a security `Verdict: BLOCK`, and vice versa. Both are checked
> separately by `release-readiness.sh`.
>
> **Copy this file to `v<version>.md`** (e.g. `v0.0.1-rc.7.md`) and fill it in.
> This `TEMPLATE.md` is the template only — it is never the sign-off for a real
> release and is ignored by the readiness check.
>
> This is evidence, not a transcript: compact observations and references, not
> raw logs or copied investigation output. See the
> [evidence contract](../../../.claude/skills/release-qa-gate/REFERENCE.md#evidence-contract)
> for the level of detail each lane's entries should carry.

- **Version:** v<version>
- **Release type / depth:** patch | rc-minor | major-deep-sweep
- **Previous tag / prior verified baseline:** v<prev-version>
- **Reviewer / executor:** <name or agent run identifier>
- **Date:** <YYYY-MM-DD>

## Baseline

- **Repository:** ai-agent-assembly/agent-assembly
- **Base branch:** main
- **Verified HEAD SHA:** `<sha>`
- **Previous trusted QA baseline:** `<sha or "none — first QA gate run">`
- **Verification manifest:** `<path or run reference, e.g. .qa/verification-manifest.json@<sha>>`

## Risk classification

- **Overall release risk tier:** LOW | MEDIUM | HIGH
- **HIGH-risk surfaces touched this release:** <list, or "none">
- **Deep-sweep triggered?** yes / no — <reason, e.g. "no — patch release, cadence not due">

## Selected journeys

| Journey ID | Priority | Reason selected | Result |
|---|---|---|---|
| <e.g. J-CLI-QUICKSTART> | P0 | always run | PASS |
| <id> | P1 | impacted by <surface> | PASS |

> Full journey catalog: AAASM-5824's machine-readable catalog. This table lists
> only the journeys actually selected and run for this release, not the whole
> catalog.

## Feature → Coverage ledger

One row per `.qa/feature-delta.json` entry (AAASM-5843) — every ticket the
feature-delta step classified for this release window, cross-referenced
against its reconciled QA coverage (AAASM-5844). `RELEASE_ELIGIBLE` features
classified `NOT_COVERED`/`STALE_COVERAGE` must show a committed journey/Story
reference here, not "pending" — see the reconciliation procedure
(`.claude/skills/release-qa-gate/REFERENCE.md#feature--qa-coverage-reconciliation`)
for the classification taxonomy.

| Ticket | Capability / summary | Coverage classification | Journey / Story reference | Evidence |
|---|---|---|---|---|
| <AAASM-XXXX> | <one-line capability summary> | COVERED / PARTIALLY_COVERED / STALE_COVERAGE / NOT_COVERED / DUPLICATE_EXISTING_COVERAGE / OUT_OF_CURRENT_RELEASE_QA_SCOPE | <journey ID + Jira Story, or "n/a"> | <lane result / run reference backing the classification> |

## Lane results

Six lanes, each: PASS / FAIL / PARTIAL / UNTESTED, one line of evidence
reference (not a full transcript).

| Lane | Result | Evidence reference |
|---|---|---|
| Functional / config | | |
| Golden journeys | | |
| Design | | |
| Reliability | | |
| Docs / product consistency | | |
| Security-relevant behavior | | |

## Skipped / blocked / untested coverage

| Item | Reason | Risk if unresolved |
|---|---|---|
| <surface/journey> | <e.g. "no test env available"> | <LOW/MEDIUM/HIGH> |

> `UNTESTED_OR_BLOCKED` on a P0 journey or a changed HIGH-risk surface is never
> silently treated as PASS — see the release QA policy's gate rules
> (`docs/src/qa/release-qa-policy.md`). If this table has such a row and it is
> not covered by an explicit waiver below, the verdict below must be BLOCK.

## Findings

| ID | Severity | Finding | Jira | Status |
|---|---|---|---|---|
| <F-1> | <Critical/High/Medium/Low> | <description> | <AAASM-XXXX or n/a> | open blocker / fixed-reverified / waived / non-blocking |

## Known non-blocking issues / residual risk

<Low/cosmetic items tracked but not gating this release. Reference Jira or state
"none".>

## Waivers

<For any normally-blocking condition a human has explicitly accepted for this
release. State who waived it, when, and why. "none" if no waiver was needed.>

- **Waived by:** <name>
- **Condition waived:** <e.g. "Medium finding F-2 on P0 path">
- **Justification:** <why the residual risk is acceptable>

## Verdict

<!-- The token `Verdict: PASS` is what release-readiness.sh greps for. -->

Verdict: PASS
