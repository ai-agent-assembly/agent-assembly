# release-qa-gate — detailed reference

The per-step detail behind [SKILL.md](SKILL.md)'s eight-step summary.

## Contents

- [The six verification lanes](#the-six-verification-lanes)
- [Step 1: verification manifest](#step-1-verification-manifest)
- [Step 2: feature-delta discovery](#step-2-feature-delta-discovery)
- [Step 3: risk mapping](#step-3-risk-mapping)
- [Step 4: depth/scope selection](#step-4-depthscope-selection)
- [Step 5: bounded parallel verification](#step-5-bounded-parallel-verification)
- [Step 6: finding verification](#step-6-finding-verification)
- [Step 7: Jira filing](#step-7-jira-filing)
- [Step 8: writing the sign-off](#step-8-writing-the-sign-off)
- [Worked example](#worked-example)
- [Troubleshooting](#troubleshooting)

## The six verification lanes

Every selected journey/surface is verified along one or more of these six
lanes (the same six the QA sign-off's lane-results table records, per
`docs/release/qa-signoff/TEMPLATE.md`):

| Lane | Owning role(s) | What it checks | Evidence contract |
|---|---|---|---|
| **Functional / configuration** | `qa-functional` | CLI commands, gateway startup/registration, policy authoring/apply, config schema behavior | CLI/command-behavior section of `docs/src/qa/evidence-and-worker-result-contract.md` |
| **Golden journeys** | `qa-sdk-journey` (SDK/install/Quick-Start/Golden-Path journeys), `qa-functional` (CLI/gateway-entry journeys) | The outside-in journeys selected in Step 4, run against the real public/documented path | Same contract's CLI/API/browser sections, per journey's `entry_point` |
| **Design** | `qa-design` | Dashboard visual/functional behavior, any journey with `browser_required: true`, CLI/TUI presentation | Browser/design-QA section of the evidence contract |
| **Reliability** | `qa-reliability-docs` | Induced failure -> recovery/degradation -> diagnostics, for HIGH-risk or explicitly reliability-tagged surfaces | Reliability/failure-path section |
| **Documentation / product consistency** | `qa-reliability-docs` | Every documented command/link in the release delta's touched docs actually works (J21) | Documentation-contract section |
| **Security-relevant behavior** | any role, escalated per AAASM-5827 | Security-relevant behavioral findings surfaced *during* QA — independent of, and never a substitute for, `/release-security-gate`'s own review | Security-relevant-behavior section |

A given run does not necessarily exercise all six lanes — Step 4's
depth/scope selection determines which lanes apply, driven by the risk
mapper's `lanes` output (`qa/risk-rules.yaml`) union'd with each selected
journey's own `lanes` field in `qa/golden-journeys.yaml`.

## Step 1: verification manifest

```bash
bash scripts/qa/build-verification-manifest.sh .
# writes .qa/verification-manifest.json (git-ignored, per-run)
```

Schema and baseline-precedence rules: `docs/release/qa-verification-manifest-schema.md`.
This runs **once**, in the coordinator — every `qa-*` worker receives a
slice of this output, never re-derives it. A stale local checkout is never
the tested baseline (the generator always resolves the canonical remote
default branch); see that doc's stale-checkout negative control.

## Step 2: feature-delta discovery

```bash
python3 scripts/qa/build-feature-delta.py
# reads baseline_sha/head_sha from .qa/verification-manifest.json unless
# --baseline-sha/--head-sha are given explicitly; writes
# .qa/feature-delta.json (git-ignored, per-run)
```

Rules: `docs/src/qa/release-qa-policy.md#feature-delta-discovery`. Cross-
checks Jira ticket status against merged `[<ticket>]`-titled PRs and
candidate-HEAD ancestry (`git merge-base --is-ancestor`), classifying every
candidate ticket `RELEASE_ELIGIBLE` or `OUT_OF_CURRENT_RELEASE_QA_SCOPE`
with a specific reason. By default the Jira query is a bounded
`resolutiondate` lookback window (`--lookback-days`, default 14) with
`status = Done` — not `fixVersion`, because that field is not reliably
populated per ticket (`--fix-version` remains available as an opt-in
override for a release lineage where it is). This runs **once**, in the
coordinator, same as the manifest — the output feeds AAASM-5844's feature →
QA-coverage reconciliation, it is not re-derived per QA worker.

**Practical invocation for a targeted re-run** (e.g. re-checking a specific
ticket set instead of the full lookback window): `--tickets
AAASM-XXXX,AAASM-YYYY` bypasses Jira JQL discovery and reconciles exactly
those keys.

**Troubleshooting an `OUT_OF_CURRENT_RELEASE_QA_SCOPE` result** — check the
entry's `evidence.reason`:

- `"ticket not Done"` — the ticket's Jira status is not Done, and no anti-
  circularity override applied (its unchecked items are not solely QA-gate-
  related). Genuine incomplete work; correctly excluded.
- `"no merged PR found referencing this ticket"` — no merged PR's title
  matched `[<ticket>] in:title` via `gh pr list`. Check whether the PR title
  actually follows the `[<ticket>]` convention (a title drift here is a real
  gap in this script's detection, not a false negative to route around) or
  the PR simply hasn't merged yet.
- `"merge commit not an ancestor of candidate HEAD"` — a merged PR was
  found, but its merge commit is not reachable from candidate HEAD (merged
  to a different branch, or the candidate build predates it). This is
  usually a genuine "not in this build" signal, not a script bug.
- Missing `JIRA_URL`/`JIRA_USERNAME`/`JIRA_API_TOKEN` produces an
  `escalations[]` entry (`jira_credentials_missing`) instead of a fabricated
  result — treat that as an environment gap to fix, never as "zero features
  in scope."

## Step 3: risk mapping

```bash
python3 scripts/qa/map-risk.py --manifest .qa/verification-manifest.json
```

Rules and composition semantics: `qa/RISK-MAPPER.md`. Output always includes
the full P0 journey set from `qa/golden-journeys.yaml`, regardless of what
matched — P0 is unconditional per the release QA policy, the mapper can only
ever add to it.

If the manifest's `baseline.source` is `"unknown"` (no prior QA sign-off
found for this release lineage), treat this as requiring **broader**
verification, per the policy — do not treat an unknown baseline as
"unchanged."

## Step 4: depth/scope selection

Apply `docs/src/qa/release-qa-policy.md`'s tier table to the risk-mapper's
`overall_risk` and `journeys` output:

- **patch**: P0 (always) + journeys/surfaces the mapper flagged as
  impacted + touched config/docs/artifacts.
- **RC/minor**: patch scope + relevant P1 journeys + a representative config
  matrix + broader SDK interoperability + any surface where a trust-boundary
  checklist row would flip.
- **major/deep-sweep**: RC/minor scope + broad P1/P2 + full adversarial pass
  + docs/examples/design audit + long-tail configurations.

**Under token/time pressure**, the policy's ordering is followed exactly:
drop P2 first, then P1, then additional impacted MEDIUM surfaces — **P0 and
changed HIGH-risk surfaces are never dropped**. If they cannot be completed
anyway, that is `UNTESTED_OR_BLOCKED`, which forces `Verdict: BLOCK` unless
explicitly waived (see Step 8).

## Step 5: bounded parallel verification

Assign the selected scope across the `.claude/agents/qa-*.md` roles per
`qa/ORCHESTRATION.md`:

- Maximum **5** concurrent workers, a ceiling not a target — a narrow patch
  scope should use 1-3.
- No nested spawning (each role's `tools:` frontmatter excludes agent-
  spawning capability).
- Reserve a slot for `qa-finding-verifier` when the scope is likely to
  surface High/Critical candidates (HIGH-risk surfaces in scope) rather than
  always filling all 5 wave-1 slots.
- Each worker receives only its manifest/journey slice — never the full
  Jira history or the full manifest for unrelated surfaces.
- Every worker returns exactly the AAASM-5828 compact schema
  (`docs/src/qa/evidence-and-worker-result-contract.md`): `STATUS / BASELINE
  / VERIFIED / SUSPECTED_FINDINGS / UNTESTED_OR_BLOCKED / CONFIDENCE`.

Where a worker needs a runtime path (CLI, docs site, an SDK), use the
persisted recipe in `qa/runtime-recipes/` rather than rediscovering launch
commands — and respect each recipe's public-artifact vs. source-development
label; never let a source-dev recipe silently stand in for an unavailable
public golden-journey path.

## Step 6: finding verification

For every `SUSPECTED_FINDINGS` entry across all workers' results, follow
`qa/FINDING-VERIFICATION-PROTOCOL.md`:

1. **Dedup** against open Bugs / this run's other findings / prior sweep
   findings / known limitations.
2. **Independent verification**: mandatory (`qa-finding-verifier`, given
   only the minimum reproduction contract) for High/Critical or any P0-
   blocker candidate; expected-when-practical for Medium; lightweight for
   Low.
3. Classify `CONFIRMED` / `REJECTED` / `INCONCLUSIVE` (treat `INCONCLUSIVE`
   as not-filed, recorded as a known issue instead).

## Step 7: Jira filing

Only `CONFIRMED` findings are filed, in the project's established Bug
structure (see the `ticket-authoring` skill and this repo's
`.claude/CLAUDE.md` JIRA conventions) — full metadata: affected SHA/version
(from the manifest), impact, independently-confirmed reproduction, expected/
actual, evidence, severity/priority, acceptance criteria, verification
method, Component = the owning repo, Team = Pioneer.

**Exception**: a confirmed defect in this gate's own infrastructure (a bug
in a `scripts/qa/*` script or a `.claude/skills/release-qa-gate/`/
`.claude/agents/qa-*` file) is fixed directly in the same PR/session rather
than filed as a product Bug — see AAASM-5829's PR (#2125) for a worked
precedent (a real `map-risk.py` bug found and fixed, not filed).

## Step 8: writing the sign-off

Copy `docs/release/qa-signoff/TEMPLATE.md` to
`docs/release/qa-signoff/v<version>.md` and fill in: baseline (from the
manifest), risk classification, selected journeys, six-lane results,
skipped/blocked coverage, findings table, known non-blocking issues,
waivers, and the final verdict line.

**Verdict rule**:

- `Verdict: BLOCK` if any P0/changed-HIGH-risk coverage is
  `UNTESTED_OR_BLOCKED` without an explicit recorded waiver, or any
  release-blocking finding (per the policy's BLOCK-condition list) is open.
- A **waiver** is a human decision — the gate does not infer one. Absent an
  explicit waiver, unresolved Medium-on-P0 or unexplained blocked mandatory
  coverage forces `BLOCK`.
- `Verdict: PASS` only when no release-blocking condition remains open and
  all mandatory (P0 + changed-HIGH) coverage is genuinely verified or
  explicitly, humanly waived.

Commit it: `📝 (release): QA sign-off for v<version>`.

After the sign-off is committed (and after any remediation loop the run
triggered, per `qa/FINDING-VERIFICATION-PROTOCOL.md`), apply
`qa/CLEANUP-PROTOCOL.md` (AAASM-5846) before reporting the campaign
complete: per-merge worktree/process teardown, a real CI-waiting mechanism,
and the final-completion bar (0 stale worktrees, 0 unnecessary background
processes, 0 leftover listeners/servers, 0 leftover temp folders).

## Worked example

A patch release touching only `aa-gateway/src/policy/mod.rs`:

```bash
bash scripts/qa/build-verification-manifest.sh .
# -> baseline unknown (first run) or resolves to the last PASS qa-signoff
python3 scripts/qa/build-feature-delta.py
# -> features: [{ticket: AAASM-1234, classification: RELEASE_ELIGIBLE,
#    merge_commit: <sha>, ...}], escalations: []
python3 scripts/qa/map-risk.py --manifest .qa/verification-manifest.json
# -> overall_risk: HIGH, lanes: [functional, reliability, security],
#    journeys: [J04,J08,J17,J19,J21,J24,J41,J53,J56,J59 (P0)] + [J25-J29 (policy P1s)]
```

Depth = patch tier -> P0 (all 10) + the impacted P1 policy journeys. Assign
`qa-functional` (policy enforcement checks) + `qa-reliability-docs` (J21
doc-integrity, since HIGH-risk surfaces changed) — 2 of 5 slots, 3 free for
`qa-finding-verifier` if either surfaces a candidate.

## Troubleshooting

- **Manifest reports `baseline.source: "unknown"`** — no prior QA sign-off
  exists for this lineage (e.g. first run of this gate). This widens scope
  per the policy; it is not an error to fix.
- **Risk mapper reports `fallback_used: true`** — some changed path matched
  no rule in `qa/risk-rules.yaml`. Verify the fallback's MEDIUM scope is
  actually sufficient; if the path is a recognizable new surface type,
  consider adding a rule (see AAASM-5829's design constraints on rule
  granularity).
- **A worker returns `BLOCKED`** — check whether it's a genuine environment
  gap (see `qa/runtime-recipes/README.md`'s "left out this round" list) vs.
  a real product defect; the finding-verification protocol's
  environment-harness classification exists for exactly this.
- **`release-readiness.sh` still fails after a PASS sign-off is committed**
  — confirm the filename matches `docs/release/qa-signoff/v<version>.md`
  exactly and the file contains the literal line `Verdict: PASS` (not
  `Verdict: PASS.` or similar) — see AAASM-5823's negative-control harness
  for the exact grep pattern.
