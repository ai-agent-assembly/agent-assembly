# Release QA policy — risk tiers, journey priority, depth and gate rules

> Governance contract for the release-QA half of the release gate (AAASM-5819).
> Consumed by [`/release-qa-gate`](../../../.claude/skills/release-qa-gate/SKILL.md)
> (AAASM-5821), the [risk mapper](../../../.claude/skills/release-qa-gate/REFERENCE.md#risk-mapper)
> (AAASM-5829) and the [QA sign-off](../../release/qa-signoff/TEMPLATE.md)
> (AAASM-5822). This page is the **selector policy** — it decides *how much*
> verification a release needs and *what blocks it*. It is not a second test
> framework and does not replace
> [AAASM-4522](https://lightning-dust-mite.atlassian.net/browse/AAASM-4522)'s
> outside-in journey inventory or the independent
> [`/release-security-gate`](../../../.claude/skills/release-security-gate/SKILL.md).

## Why a selector policy

Prior sweeps (AAASM-3198, AAASM-4522, the AAASM-4651/4690 lineage) proved that a
full-codebase/full-doc re-audit finds real drift, but repeating that depth on
every patch spends context on unchanged low-risk surfaces before the paths that
actually matter are exercised. This policy makes "how much is enough" a
deterministic lookup instead of something the LLM reinvents every run.

## Feature delta discovery

> Governs [`scripts/qa/build-feature-delta.py`](../../../scripts/qa/build-feature-delta.py)
> (AAASM-5843), which runs between manifest generation and risk mapping (see
> [`/release-qa-gate`](../../../.claude/skills/release-qa-gate/SKILL.md)'s
> run procedure). It answers a different question than risk mapping does:
> risk mapping classifies *changed paths*; feature delta discovery answers
> "what product capabilities actually completed in the baseline→candidate
> window" — a file list is not a capability list.

Neither Jira status nor git history is trustworthy alone for "what shipped
this release": a ticket can be marked Done with its implementation PR still
open, and a merged PR can reference a ticket whose branch never reached the
candidate build. Feature delta discovery cross-checks both signals against
each other and reports disagreement rather than guessing.

### Eligibility rules

A ticket is `RELEASE_ELIGIBLE` only when **all** of the following hold:

1. The ticket's Jira status is Done (or the anti-circularity rule below
   applies).
2. At least one merged PR exists whose title matches the `[<ticket>]`
   convention.
3. That PR's merge commit is a real ancestor of candidate HEAD
   (`git merge-base --is-ancestor`, not just "referenced somewhere").

Any other outcome is `OUT_OF_CURRENT_RELEASE_QA_SCOPE`, with one of three
specific reasons: `"ticket not Done"`, `"no merged PR found referencing this
ticket"`, or `"merge commit not an ancestor of candidate HEAD"`.

### Anti-circularity rule

A ticket whose only remaining unchecked acceptance criterion or comment
references this Epic's own QA-gate execution ("QA sign-off", "release QA
gate", "QA-complete") must not be excluded for "not Done" on that basis
alone — the eligibility check is about the *feature's own* implementation
completion, not this Epic's gate having run yet. When a ticket's Jira status
is not Done but its only unchecked item is gate-related **and** its
implementation PR is merged with a merge commit that is a real ancestor of
candidate HEAD, it is still classified `RELEASE_ELIGIBLE`, with the
override recorded explicitly in the evidence. A ticket with any other
genuinely unfinished item does not get this override.

### Classification taxonomy

| Classification | Meaning |
|---|---|
| `RELEASE_ELIGIBLE` | Done (or anti-circularity-overridden) + merged PR + merge commit is a real ancestor of candidate HEAD. |
| `OUT_OF_CURRENT_RELEASE_QA_SCOPE` | One of the eligibility conditions failed; the specific reason is always recorded in the evidence, never a bare exclusion. |

Output is a single git-ignored per-run artifact, `.qa/feature-delta.json`
(same convention as the verification manifest), consumed by AAASM-5844's
feature → QA-coverage reconciliation — it is not re-derived per QA worker.

## Risk tiers

Every changed path/surface is classified LOW, MEDIUM or HIGH. The mapping from
path to tier is mechanical — see the
[risk mapper](../../../.claude/skills/release-qa-gate/REFERENCE.md#risk-mapper);
this section defines what each tier means.

### HIGH

Any of the following, changed or newly introduced:

- Authentication / authorization (`aa-auth/`, `aa-security/`).
- Tenant isolation (cross-org/cross-team data boundaries).
- Policy enforcement (`aa-gateway/src/policy/`, `aa-policy/`).
- Proxy / network egress (`aa-proxy/`).
- IPC / local trust boundary (`aa-runtime/src/pipeline/`, SDK↔runtime bridge).
- Secrets / sensitive-data handling (credential scanning, secret injection,
  audit sinks).
- Persistence / storage layers that hold tenant data (`aa-storage*`).
- Privileged execution (`aa-ebpf*`, `aa-isolation*`, `aa-sandbox`).
- Package / release supply chain (`scripts/release-*.sh`, `.github/workflows/
  release.yml`, publish workflows, signing).
- Billing / entitlements.
- Any **fail-open ↔ fail-closed** change in enforcement behavior, in either
  direction.

### MEDIUM

Product-facing behavior that is not a HIGH surface but is user-visible and not
purely cosmetic: CLI subcommand behavior, dashboard functional behavior, SDK
public API surface, config schema, documented commands/examples, budget
tracking, non-security reliability paths.

### LOW

Internal refactors with no observable behavior change, test-only changes,
comment/formatting changes, dependency bumps with no advisory, and non-normative
documentation (typos, wording).

**Unmapped / unknown paths default to MEDIUM, never LOW** — see the risk
mapper's fallback rule (AAASM-5829). Silent downgrade of an unrecognized path is
not acceptable.

## Journey priority (P0 / P1 / P2)

[AAASM-4522](https://lightning-dust-mite.atlassian.net/browse/AAASM-4522)
remains the durable outside-in journey inventory and the human-readable source
of truth. This policy adds a priority label per journey, captured in the
machine-readable catalog (AAASM-5824):

- **P0 — always executed, every release.** Invariant, release-critical paths:
  primary install/Quick Start, primary SDK smoke path, gateway startup +
  registration, policy enforcement allow/deny, auth happy-path, one full
  golden-journey walkthrough per supported entry point (CLI, one SDK, one API
  surface). Kept deliberately small — **8–15 journeys** — so "always run" stays
  economical. The exact initial P0 set is enumerated in the catalog, not
  duplicated here, so it has one source of truth.
- **P1 — executed when impacted, and on RC/minor and above.** Important but not
  release-invariant paths: secondary SDKs, dashboard secondary flows, budget/
  alerting, config matrix variants, secondary install paths.
- **P2 — long-tail, deep-sweep only.** Rare configurations, edge-case journeys,
  exhaustive matrix combinations, historical regression journeys kept for
  archival coverage.

A journey runs when: it is P0 (always), or it is P1/P2 **and** the risk mapper
marks its surface impacted, or it is P1/P2 **and** the release tier requires it
regardless of impact (see Verification depth below).

## Verification depth (additive by release tier)

Tiers are **additive** — each adds to the one before it, mirroring
`/release-security-gate`'s patch/minor/major model.

| Tier | Scope |
|---|---|
| **Patch / small iteration** | All P0 journeys **+** changed/impacted surfaces (per risk mapper) **+** touched config/docs/artifacts **+** release-diff security-relevant behavior checks. |
| **RC / minor** | Patch **+** relevant P1 journeys **+** a representative config matrix **+** broader SDK interoperability **+** design/reliability coverage on touched surfaces **+** any changed trust boundary (cross-check against the security trust-boundary checklist). |
| **Major / periodic deep sweep** | RC/minor **+** broad P1/P2 journey set **+** full adversarial QA/security review **+** docs/examples/design audit **+** long-tail configuration coverage **+** threat-model-aligned deep-sweep work. |

**Under token/time pressure, depth is reduced from the bottom of this table
up** — P2 before P1, P1 before "additional impacted MEDIUM surfaces," and so
on. **P0 journeys and changed HIGH-risk surfaces are never dropped to save
budget.** If a run cannot complete P0 + changed-HIGH coverage, it must record
those as `UNTESTED_OR_BLOCKED` and the sign-off must reflect that (see Gate
policy) rather than silently shrinking scope.

## Negative-control policy (AAASM-5877)

A passing test is only useful assurance if it would reliably fail when the
protected property is actually broken. This policy makes "does this journey
need a demonstrated negative control" a deterministic lookup rather than a
per-ticket judgment call, mirroring how [Risk tiers](#risk-tiers) already
does this for depth.

**Mandatory class**: a `release_blocking: true` + `lifecycle_state:
automated` [registry](../../../qa/golden-journeys.yaml) entry on the
`security` lane must declare a non-empty `negative_control` field — enforced
mechanically by `scripts/qa/validate-golden-journeys.py`
(`AAASM-5877`). A security-blocking claim with no evidence it fails when
broken is not release-blocking evidence, regardless of how green its
positive path is.

**What counts as a negative control**: a reference to executable evidence
that (1) exercises the protected invariant in a genuinely broken state
(a real fault/mutation, not a hypothetical), (2) asserts the expected
non-PASS outcome, and (3) — where the test doesn't already restore state
itself — leaves no weakened production/default state behind. A one-line
free-text pointer (e.g. `aa-cli/tests/run_policy_fail_closed.rs
(fail-closed regression)`) is sufficient; the policy does not require a
structured schema beyond "this is real, resolvable, and demonstrates
failure," matching this catalog's existing "thin index, not a test-plan"
design (see `qa/README.md`).

**Freshness**: a negative control's *presence* is validated on every
registry-health run (AAASM-5876); a negative control's own *pass/fail
result* follows the same execution-lane/freshness rules as the journey's
positive evidence — it does not need re-execution on every PR merely
because the field is required, only when its declared `execution_lanes`
say so.

**Beyond the mandatory class**: P1/P2 or non-security journeys are not
required to declare a negative control by this policy, but adding one when
a real fault/mutation is cheap and specific to that journey is always
encouraged — see `qa/README.md`'s negative-control section for the
currently demonstrated examples across the security-enforcement,
cross-process-evidence, and registry/CI-execution-integrity classes.

## Gate policy — BLOCK / waiver rules

`Verdict: BLOCK` on any of:

- Critical/High security-relevant defect discovered during QA (folds into, and
  is independent of, `/release-security-gate`'s own verdict).
- Authentication/authorization or tenant-isolation bypass.
- Sensitive-data exposure, or data corruption/loss.
- A security-sensitive fail-open regression.
- A broken P0 golden journey.
- A broken primary installation / Quick Start path.
- An unusable primary SDK.
- A broken required release artifact.
- A core policy/runtime enforcement regression.
- Mandatory P0 or changed-HIGH-risk coverage that is `UNTESTED_OR_BLOCKED` and
  not explicitly waived (see below) — unverified is not PASS.

**Medium** severity findings on P0 or otherwise-critical paths require either a
fix + reverification, or an explicit human waiver recorded in the sign-off
artifact (who, why, accepted residual risk). They cannot be silently dropped.

**Low / cosmetic / non-blocking docs issues** may PASS the gate, but only when
tracked (a Jira reference or an explicit "known issue" line in the sign-off) —
untracked is not the same as accepted.

A waiver is a human decision, not something the QA gate infers. Absent an
explicit waiver, unresolved Medium-on-P0 or any unexplained
`UNTESTED_OR_BLOCKED` mandatory coverage forces BLOCK.

## Escalation hatch

When the automated risk classification is genuinely ambiguous (a changed path
does not clearly map to an existing tier, or a change plausibly straddles
HIGH/MEDIUM) **and** the ambiguity materially changes release depth (P0-only vs.
pulling in extra P1/P2 or trust-boundary review), the gate must escalate to a
human decision rather than silently pick the cheaper interpretation. Record the
escalation and its resolution in the verification manifest (AAASM-5825) and/or
the sign-off.

## Periodic deep-sweep trigger

A major/periodic deep sweep (P1/P2 broad set + full adversarial pass) is
triggered by **any** of:

- A major SemVer release, or a pre-release channel promotion (e.g.
  `…beta.N` → `…rc.1`) — mirrors `/release-security-gate`'s tier detection.
- A material architecture or trust-boundary change (any row in the security
  trust-boundary checklist flips to Y).
- Cadence: no full deep sweep has run in the last **10 releases or 60 days**,
  whichever comes first (mirrors the AAASM-4651/4690 sweep cadence already in
  use). The verification manifest records the last deep-sweep baseline so this
  is a lookup, not a re-derivation.

Deep sweep is **not** mandatory for every patch — that is the entire point of
having a risk-based selector instead of a fixed full-scan prompt.

## Relationship to `/release-security-gate`

This policy and the QA gate it drives are **additive to, and independent of**,
the security gate. QA does not weaken, replace, or gate the security sign-off,
and the security sign-off's `Verdict: BLOCK` is never overridden by a QA
`Verdict: PASS` (`scripts/release-readiness.sh` checks both independently — see
AAASM-5823). Security-relevant behavioral findings discovered during QA are
still classified and can independently force QA `Verdict: BLOCK`, but they do
not edit the security sign-off artifact.

## Non-goals

- This page does not execute the QA campaign — see `/release-qa-gate`
  (AAASM-5821).
- It does not re-enumerate every AAASM-4522 journey — see the machine-readable
  catalog (AAASM-5824) for the actual P0 set and per-journey classification.
- It is not a test-case management platform.
