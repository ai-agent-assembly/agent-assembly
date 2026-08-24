# release-qa-gate — detailed reference

The per-step detail behind [SKILL.md](SKILL.md)'s eight-step summary.

## Contents

- [The six verification lanes](#the-six-verification-lanes)
- [Step 1: verification manifest](#step-1-verification-manifest)
- [Step 2: feature-delta discovery](#step-2-feature-delta-discovery)
  - [Feature → QA-coverage reconciliation](#feature--qa-coverage-reconciliation)
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

### Feature → QA-coverage reconciliation

> AAASM-5844. Runs immediately after feature-delta discovery, still in the
> coordinator (never per-worker) — it consumes `.qa/feature-delta.json`'s
> `RELEASE_ELIGIBLE` list, the same output Step 2 just produced. This is the
> mechanism that makes feature-delta discovery *actionable*: without it,
> AAASM-5843's output is a list nobody checks against durable QA
> representation, and a shipped capability can sail through with zero
> golden-journey or Story coverage while every pre-existing journey shows
> green.

For every `RELEASE_ELIGIBLE` feature-delta entry, trace: implementation work
→ product capability → user/persona outcome → existing QA Jira Story →
`qa/golden-journeys.yaml` catalog entry → executed evidence, and land on
exactly one of six classifications.

#### The mechanical pre-filter (script)

```bash
python3 scripts/qa/build-feature-delta.py            # Step 2, already run
python3 scripts/qa/check-feature-coverage.py
# reads .qa/feature-delta.json + qa/golden-journeys.yaml; writes
# .qa/coverage-candidates.json (git-ignored, per-run — same convention as
# .qa/feature-delta.json and .qa/verification-manifest.json)
```

[`scripts/qa/check-feature-coverage.py`](../../../scripts/qa/check-feature-coverage.py)
does exactly one mechanical thing per `RELEASE_ELIGIBLE` ticket: does **any**
journey's `feature_refs` list contain it? Zero references →
`NOT_COVERED_CANDIDATE`. One or more → `REFERENCED`, with the list of
referencing journey IDs. It cannot and does not judge whether a `REFERENCED`
ticket is actually well-covered — that is the coordinator judgment below.
The output is a separate file from `feature-delta.json` rather than a
mutation of it: that schema is owned by AAASM-5843's script and consumed
elsewhere, and nothing downstream needs the two merged into one document.

#### The classification taxonomy (coordinator judgment)

A `NOT_COVERED_CANDIDATE` from the mechanical filter is not automatically
final — the coordinator confirms it (see durable-coverage-creation below). A
`REFERENCED` ticket needs the coordinator to pick one of the remaining five
classifications by comparing the feature's *actual* shipped scope against
the referencing journey's/Story's *stated* scope, thinking as a senior QA
engineer would: persona and realistic intent, the golden path, realistic
failure paths (not just the happy path), configuration/environment variance,
reliability and degraded behavior, the trust boundary the feature touches (if
any), and forbidden side effects — not merely translating source diff lines
into a test-case list.

| Classification | Meaning | Worked example |
|---|---|---|
| `COVERED` | A journey's `feature_refs` names the ticket, and the journey's stated scope genuinely still describes the feature's current behavior. | **AAASM-3952** ("Add component and profile support to install.sh", real, `Done`, merged — a prior ticket, not itself in this ticket's rc.6→HEAD reconciliation window; cited here only to prove the mechanical check recognizes a real reference, `--tickets` was used to bypass window discovery for this proof) is referenced by **J04** ("Install the aasm CLI (install.sh / Homebrew / version pin / profiles)"). J04's own scope already names install.sh's profile/component behavior as part of what it verifies — the feature and the journey describe the same golden path, and AAASM-3952 didn't change install.sh's fundamental contract (still a shell script fetched and run, still installs `aasm`). `check-feature-coverage.py` reports this `REFERENCED`; the coordinator confirms `COVERED` because the journey's stated scope is not stale relative to the shipped feature. |
| `PARTIALLY_COVERED` | A journey references the ticket, but the journey's stated scope only exercises part of what the feature actually does — a real gap remains, not a full miss. | *Realistic*: suppose a future ticket extended `install.sh` to also support an air-gapped/offline install mode (fetching a pre-downloaded tarball instead of curling GitHub), and a coordinator added it to J04's `feature_refs` without updating J04's `surfaces`/`outcome` to mention the offline path. J04's golden-path install still runs and still passes, but the new offline-install failure path (bad tarball checksum, missing local cache dir) is never exercised by anything J04 actually runs — the reference exists, the coverage is incomplete. |
| `STALE_COVERAGE` | A journey references the ticket, but the feature was materially redesigned and the journey/Story still describes the *old* behavior — the reference is present but no longer true. | *Realistic*: if AAASM-5832/5833's gateway start/status liveness fixes (PID-exists-but-dead-process, AddrInUse-but-reports-success) were later attached to **J17** ("Install & run the gateway from a published artifact") without updating J17's outcome text, and a subsequent redesign replaced the PID-file liveness check with a socket-based health probe entirely, J17's still-referenced acceptance contract would describe a PID check that no longer exists in the code — `STALE_COVERAGE`, not `COVERED`, because the referencing journey's stated mechanism and the feature's actual mechanism have diverged. |
| `NOT_COVERED` | No journey's `feature_refs` names the ticket, and no open/recent QA Story covers it either — confirmed by the coordinator after the mechanical filter's `NOT_COVERED_CANDIDATE` flag. | **AAASM-5832** and **AAASM-5833** (real, from this Epic's own `v0.0.1-rc.7` window): both are genuine shipped bug fixes to `aasm gateway start`/`status` liveness reporting, and as of this writing zero journey in `qa/golden-journeys.yaml` lists either in `feature_refs`. `check-feature-coverage.py` flags both `NOT_COVERED_CANDIDATE`; the coordinator confirms `NOT_COVERED` (no Story references them either) and proceeds to durable-coverage-creation. |
| `DUPLICATE_EXISTING_COVERAGE` | Two related, `RELEASE_ELIGIBLE` features would each independently need a new journey/Story, but an existing journey already exercises materially the same golden path for both — creating a second, near-identical entry would be redundant, not additive. | *Realistic*: AAASM-5832 (gateway *start* reports false success) and AAASM-5833 (gateway *status* reports a dead PID as alive) are two separate tickets, but both are the same underlying persona action — "operator runs a gateway lifecycle command and trusts its liveness claim" — and a single new journey ("verify `aasm gateway start`/`status`/`stop` liveness reporting is honest") can cover both `feature_refs` at once. Filing two near-identical journeys (one per ticket) instead of one combined journey with `feature_refs: [AAASM-5832, AAASM-5833]` would be `DUPLICATE_EXISTING_COVERAGE` avoided correctly; filing them separately anyway is the anti-pattern this classification exists to catch. |
| `OUT_OF_CURRENT_RELEASE_QA_SCOPE` | The ticket is `RELEASE_ELIGIBLE` per feature-delta discovery, but it is not a user-facing product capability that golden-journey coverage applies to at all — it is this gate's own infrastructure, internal tooling, or process/documentation change. | **AAASM-5819** and **AAASM-5831** (real, same window): both ship changes to `docs/release/qa-signoff/` and `docs/release/security-signoff/` — this Epic's own QA-gate infrastructure and sign-off artifacts, not a product capability an end user or operator experiences. Confirming this: `python3 scripts/qa/map-risk.py "docs/release/qa-signoff/v0.0.1-rc.7.md" "docs/release/security-signoff/v0.0.1-rc.7.md"` matches **no** rule in `qa/risk-rules.yaml` (falls through to the unmapped-path fallback, `journeys: []`) — there is no golden journey for "the QA gate verifies its own sign-off doc," and there should not be one. The coordinator classifies these `OUT_OF_CURRENT_RELEASE_QA_SCOPE` for reconciliation purposes and does not create a Story/journey for them, distinct from feature-delta discovery's own `OUT_OF_CURRENT_RELEASE_QA_SCOPE` (a different taxonomy answering "did this ship in this build," not "does this need golden-journey coverage"). |

#### Durable-coverage creation (when `NOT_COVERED` or `STALE_COVERAGE`)

When the coordinator lands on `NOT_COVERED` or `STALE_COVERAGE`, create or
update **one** durable QA Story and its corresponding catalog entry — never
a text recommendation alone (AAASM-5844's acceptance criteria require the
real artifacts). Follow AAASM-4522's established convention exactly, not a
new format:

1. **Jira Story**, filed directly under the dedicated-QA Epic
   (AAASM-4522) — verified against two real existing children (AAASM-4532,
   AAASM-4542, both created 2026-07-13) field-by-field rather than assumed,
   with one field cross-checked against a current ticket (AAASM-5844 itself,
   August) since the two disagreed:

   | Field | Real observed value | Note |
   |---|---|---|
   | `issuetype` | `Story` | Not Task/Bug — every AAASM-4522 child is a Story. |
   | `parent` | `AAASM-4522` | Direct child, no intermediate Task. |
   | `summary` | `[Journey NN · <Persona track>] <user-goal phrased summary>` | e.g. `[Journey 19 · Policy] Author, validate, simulate, and apply a policy` (AAASM-4532, real). `<Persona track>` matches the new/updated catalog entry's `persona_track`; `NN` is the new entry's `id` number. |
   | native `components` | `["agent-assembly"]` | The two 2026-07-13 AAASM-4522 children left this empty and used `customfield_10041` instead — but AAASM-5844 itself (August, current) carries native `components: ["agent-assembly"]` with `customfield_10041: null`, confirming this repo's `.claude/CLAUDE.md` policy ("native Components field, not `customfield_10041`") is the *current* convention and the two sampled AAASM-4522 children predate it. Set native `components`, not `customfield_10041`, for a new Story. |
   | `customfield_10001` (Team) | `Pioneer` | Matches the general repo policy on all three sampled tickets. |
   | `priority` | `Medium` | Both AAASM-4522 children sampled; not tied to the journey's P0/P1/P2 catalog priority (a separate concept — see step 2). |
   | `fixVersions` | The release the Story was verified against (e.g. `agent-assembly v0.0.1-rc.5`) | Set to the version this reconciliation run is targeting, not left empty. |
   | `labels` | Free-form tags: persona/category (`cli`, `install`, `policy`), `smoke-test`, `track-<persona>`, `user-journey-sim` | Not a fixed enum — both observed Stories carry `smoke-test` + `user-journey-sim` + a `track-*` label; add labels matching the new journey's own persona/surface. |
   | `description` | Markdown with fixed sections: `## User journey` (persona-voice narrative), `## Repo / entry point` (repo + concrete file paths), `## Expected result`, `## Acceptance criteria` (`- [ ]` checkbox items), optionally `## Scenarios covered`, ending `Failures → file a Bug sub-ticket linked to this Story.` | Follow this exact section shape — it is what both real children use, not a template invented for this ticket. |

   One Story per meaningful journey/workflow/boundary — **not** one Story
   per microscopic test case; fine-grained cases live inside the Story's own
   acceptance/test matrix, per this ticket's non-goals.
2. **`qa/golden-journeys.yaml` entry**: next sequential `id` (`J<NN+1>`),
   `jira:` pointing at the new Story from step 1 (not the implementation
   ticket), `feature_refs:` pointing at the implementation ticket(s) this
   journey now covers, and `priority` assigned per
   `docs/src/qa/release-qa-policy.md#journey-priority-p0--p1--p2`'s existing
   P0/P1/P2 rules (release-invariant → P0, impacted-and-important → P1,
   long-tail → P2) — reconciliation does not invent a separate priority
   scheme.
3. Run `python3 scripts/qa/validate-golden-journeys.py` after the edit —
   it validates `feature_refs`' format (non-empty list of `AAASM-*` keys)
   alongside the catalog's existing required-field/duplicate/P0-count checks.

`STALE_COVERAGE` follows the same two-artifact update, but on the
**existing** journey/Story rather than creating new ones — refresh the
Story's/journey's stated scope to match the feature's current behavior; do
not also create a duplicate new entry for the same capability.

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
`overall_risk` and `journeys` output, **unioned** with the
feature-selected journey set from the reconciliation step above: for every
`COVERED`/`PARTIALLY_COVERED`/`STALE_COVERAGE`-classified `RELEASE_ELIGIBLE`
feature, include the journey(s) its `feature_refs` names, even when no risk
rule independently matched that feature's changed paths. This union lives
here, in the coordinator's own scope-selection step, rather than as a second
input source inside `scripts/qa/map-risk.py` — that script's one job is
deterministic path → risk/lane/journey mapping from `qa/risk-rules.yaml`
(AAASM-5829); folding in a second, unrelated input (feature-delta output) it
was never validated against would blur that contract for no benefit, since
the coordinator already holds both `map-risk.py`'s output and the
reconciliation's classified list at this point and can union two ID lists
without a script change.

**Why the union matters (real case, both sets printed, not hypothetical):**
**AAASM-5715** ("Document capability-governed execution, isolation
boundaries and backend support truthfully", real merged PR #2057, `Done`,
confirmed `RELEASE_ELIGIBLE` by `build-feature-delta.py`) touched twelve
files, all under `docs/src/` (`SUMMARY.md`, `architecture/*`, `cli/*`,
`quick-start/requirements.md`, `security/*`, `usage-guide/examples.md`,
`usage-guide/troubleshooting.md`). Feeding that real path list to
`python3 scripts/qa/map-risk.py <the 12 paths>` matches only the
`docs/src/` rule → `journeys: [J21]` (plus the always-included P0 set) —
**J22** ("Recover from a failure using the troubleshooting / FAQ docs", P2,
not in the P0 set) never appears in risk-mapper output for this ticket, even
though the PR added 36 lines directly to
`docs/src/usage-guide/troubleshooting.md` — exactly J22's own subject
matter. `qa/golden-journeys.yaml` now records `J22: feature_refs:
[AAASM-5715]` (added as part of this reconciliation), and
`scripts/qa/check-feature-coverage.py` confirms it: `AAASM-5715 ->
REFERENCED -> [J22]`. **The union**
(risk-mapper's `{P0} ∪ {J21}`) **∪** (reconciliation's `{J22}`) = `{P0, J21,
J22}` — a real, provable superset of risk-rule selection alone, which stops
at `{P0, J21}` no matter how many times it is re-run against these same
paths. This is the general shape of the gap the union closes: any capability
whose real user-facing effect (a troubleshooting-doc journey, here) lives in
a different journey than the one its raw changed-path pattern happens to
match.

- **patch**: P0 (always) + journeys/surfaces the mapper flagged as
  impacted + touched config/docs/artifacts + reconciliation-referenced
  journeys for this run's `RELEASE_ELIGIBLE` features.
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

- Maximum **10** concurrent workers (AAASM-5845), a ceiling not a target — a
  narrow patch scope should use 1-3.
- No nested spawning (each role's `tools:` frontmatter excludes agent-
  spawning capability).
- Reserve a slot for `qa-finding-verifier` when the scope is likely to
  surface High/Critical candidates (HIGH-risk surfaces in scope) rather than
  always filling every wave-1 slot.
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
doc-integrity, since HIGH-risk surfaces changed) — 2 of 10 slots, 8 free for
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
