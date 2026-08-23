# Independent finding verification and defect-filing protocol

Turns the AAASM-4651/4690 discipline (hand-verify load-bearing findings at
the exact tested HEAD before filing) into a durable rule for
`/release-qa-gate` (AAASM-5821), so no automated worker's suspicion becomes a
Jira Bug on its own say-so.

## Lifecycle

```text
SUSPECTED -> DEDUPED -> INDEPENDENTLY_VERIFIED -> CONFIRMED | REJECTED -> FILED
```

| State | Meaning | Who moves it |
|---|---|---|
| `SUSPECTED` | A `qa-*` worker's `SUSPECTED_FINDINGS` entry (AAASM-5828 schema). Not yet a Bug candidate. | worker |
| `DEDUPED` | Checked against existing open Bugs, current-Epic findings, prior sweep findings, and accepted/known limitations. If a match exists, this finding is annotated onto the existing issue instead of becoming a new candidate. | coordinator |
| `INDEPENDENTLY_VERIFIED` | A second, different agent (`qa-finding-verifier`) attempted independent reproduction using only the minimum reproduction contract — not the first worker's reasoning. | qa-finding-verifier |
| `CONFIRMED` / `REJECTED` | Verifier's verdict. `INCONCLUSIVE` (see the agent's output contract) is treated as `REJECTED` for filing purposes — insufficient evidence never files a Bug, it goes to the sign-off's known-issues section instead. | coordinator, from the verifier's verdict |
| `FILED` | A Jira Bug is opened, in the project's established Bug structure. | coordinator, only after `CONFIRMED` |

A `SUSPECTED_FINDINGS` entry is **never** automatically a Bug. Only
`CONFIRMED` entries are filed.

## Deduplication (before verification)

Before spending a verifier slot, the coordinator checks:

1. Existing open Bugs for the affected surface (`jql: project = AAASM AND
   issuetype = Bug AND status != Done AND text ~ "<surface>"`).
2. Findings already recorded in the current release-QA run (two workers may
   independently notice the same thing).
3. Prior sweep/release findings (AAASM-4651/4690 lineage, prior QA sign-offs'
   findings tables).
4. Accepted/known limitations already documented (e.g.
   `docs/src/devtools/limitations.md`, prior sign-off "known non-blocking
   issues" sections).

A duplicate is **linked/annotated**, not re-filed — comment on the existing
issue with the new evidence/SHA if it adds anything, otherwise just note the
match in the sign-off's findings table with a reference to the existing key.

## Independent verification requirements by severity

| Severity | Requirement |
|---|---|
| **High / Critical, or any P0-release-blocker candidate** | **Mandatory** second independent reproduction by `qa-finding-verifier` (or the coordinator itself acting in that capacity, but never the same agent instance that reported it). The reporting worker is never the sole authority on its own High/Critical finding. |
| **Medium** | Independent verification **expected when practical**. If verifier slots are genuinely constrained (see AAASM-5826's 5-worker ceiling), the coordinator may verify directly — but this is a fallback, not the default. |
| **Low / cosmetic** | Lightweight confirmation is sufficient (the coordinator re-reads the worker's cited evidence and agrees it's concrete), but still requires actual evidence — not "it's probably fine to skip verifying this." |

Environment/test-harness failures are classified separately from product
defects at this stage — see the `qa-finding-verifier` output contract's
`CLASSIFICATION` field (`product-defect` vs.
`environment-harness-artifact`). An `environment-harness-artifact`
classification never files a Bug; it's noted in the run's internal record
(and, if it recurs, may itself become a ticket about the QA infrastructure —
tracked separately from product defects per §7 of the Epic's operating
rules).

## What the verifier receives (bias control)

Per AAASM-5828's evidence contract and the `qa-finding-verifier` agent
definition: the **minimum reproduction contract** —

- affected surface + tested SHA/version,
- expected vs. actual,
- the reported reproduction steps/command,
- severity as reported.

**Not** included: the reporting worker's speculative reasoning about *why*
it happens. This is deliberate — a verifier primed with "I think it's a race
condition in X" is more likely to confirm a race-condition-shaped
explanation than to independently discover what's actually happening.

## Jira filing (CONFIRMED only)

Confirmed defects use this project's **established Bug-specific ticket
style** (not the Story/Task style of this implementation Epic — per
`~/.claude/CLAUDE.md`'s Skill Invocation Guide, the `ticket-authoring` skill
encodes the type-specific description schema). Populate at minimum:

- affected SHA/version (from the verification manifest, AAASM-5825),
- user/security impact,
- reproduction steps (from the verifier's independently-confirmed
  reproduction, not the first worker's version),
- expected vs. actual,
- evidence (per AAASM-5828's evidence contract for the relevant surface),
- severity/priority,
- acceptance criteria for the fix,
- verification method for closing it,
- correct metadata: Component = the owning repo, Team = Pioneer, parent/
  relationship to this release's QA sign-off (comment reference) and, where
  relevant, to this Epic (AAASM-5819) or the specific child ticket whose
  scope surfaced it.

Do not silently fix a confirmed defect inside the release-QA gate's own
work — file it and let it be picked up as separate work, per the Epic's
operating rules (§7). The one exception: a defect in the QA *infrastructure
itself* (this Epic's own scripts/skills) is fixed directly, not filed as a
product Bug — see AAASM-5829's PR (#2125) for a worked example of that
distinction (a bug in `map-risk.py` found during self-review, fixed in the
same PR, not filed as a product Bug because it isn't one).

## Demonstration (AAASM-5827 AC)

`qa/finding-protocol-demo.md` walks one true finding and one false/duplicate
candidate through both branches of this protocol.
