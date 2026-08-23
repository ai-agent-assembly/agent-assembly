---
name: release-qa-gate
description: Run the release-gate QA review for an agent-assembly release, scaled by risk (patch / RC-minor / major-deep-sweep). Performs baseline discovery (verification manifest) -> risk mapping -> P0/P1/P2 journey selection -> bounded parallel verification (max 10 qa-* sub-agents) -> independent finding verification -> Jira defect filing -> autonomous same-campaign remediation of ordinary confirmed defects -> committed QA sign-off -> Verdict PASS|BLOCK. Composes with, and never replaces, /release-security-gate — both sign-offs are independently required by scripts/release-readiness.sh. Use as a stage-0 pre-cut gate before /release-tag-cut, alongside /release-security-gate. NOTE: this is the QA half of the release gate — distinct from /release-security-gate, which owns security sign-off.
---

# release-qa-gate

The **release-gate QA review**. It runs *before* a release tag is cut,
scales verification depth to release risk, and produces a committed
**QA sign-off artifact** that `scripts/release-readiness.sh` enforces
independently of (and additively to) the existing security sign-off. A
release with `UNTESTED_OR_BLOCKED` mandatory P0/HIGH-risk coverage, or an
unresolved release-blocking finding, **cannot** proceed with `Verdict: PASS`.

This gate composes eight pieces built for AAASM-5819 rather than reinventing
QA orchestration in a single giant prompt every run:

| Piece | Ticket | What it provides |
|---|---|---|
| [Release QA policy](../../../docs/src/qa/release-qa-policy.md) | AAASM-5820 | Risk tiers, P0/P1/P2 priority, verification depth by release tier, BLOCK/waiver rules, deep-sweep triggers |
| [QA sign-off template](../../../docs/release/qa-signoff/TEMPLATE.md) | AAASM-5822 | The committed `Verdict: PASS\|BLOCK` artifact this gate writes |
| [Golden-journey catalog](../../../qa/golden-journeys.yaml) | AAASM-5824 | Machine-readable P0/P1/P2 index over AAASM-4522 |
| [Verification manifest generator](../../../scripts/qa/build-verification-manifest.sh) | AAASM-5825 | One-shot baseline/delta/CI-state discovery, shared by every worker |
| [`.claude/agents/qa-*.md`](../../agents/) + [orchestration policy](../../../qa/ORCHESTRATION.md) | AAASM-5826 | 5 reusable roles, hard 10-concurrent ceiling, no nested spawning |
| [Finding-verification protocol](../../../qa/FINDING-VERIFICATION-PROTOCOL.md) | AAASM-5827 | SUSPECTED->DEDUPED->INDEPENDENTLY_VERIFIED->CONFIRMED\|REJECTED->FILED |
| [Evidence contract + worker result schema](../../../docs/src/qa/evidence-and-worker-result-contract.md) | AAASM-5828 | What counts as evidence; the compact result shape every worker returns |
| [Risk mapper](../../../qa/risk-rules.yaml) + [`scripts/qa/map-risk.py`](../../../scripts/qa/map-risk.py) | AAASM-5829 | Deterministic changed-path -> risk/lane/journey selection |
| [Runtime recipes](../../../qa/runtime-recipes/) | AAASM-5830 | Persisted install/build/verify/cleanup for repeated QA entry points |

This SKILL.md is a lean overview; the run procedure detail lives in
[REFERENCE.md](REFERENCE.md).

## Where this sits in the release relay

Runs alongside `/release-security-gate` as a **stage-0 pre-cut gate**, before
`/release-tag-cut` (see [`release-tag-cut/SKILL.md`](../release-tag-cut/SKILL.md)
for the full relay):

0. **`/release-security-gate <version>`** — independent security review and
   sign-off. **`/release-qa-gate <version>`** (this skill) — independent QA
   review and sign-off. Run both; neither substitutes for the other.
1. **`/release-tag-cut <version>`** — bump + tag + push. Pre-conditions now
   require **both** a security `Verdict: PASS` and a QA `Verdict: PASS` for
   `<version>` (enforced by `scripts/release-readiness.sh` checks 11 and 12).
2. fan-out (automatic, `release.yml`).
3. `/release-validate-channels v<version>` (read-only).
4. `/homebrew-tap-merge <PR>` (write, tap repo).

## When to use

- Preparing to cut a release tag and need the mandatory pre-cut QA sign-off
  (every patch/RC/major).
- Re-running after fixing/waiving a blocker, to flip a prior **BLOCK** to
  **PASS**.

Triggering phrasing: *"Release QA gate rc.7"*, *"Run the release QA gate for
0.0.1-rc.7"*, *"Sign off QA before we tag"*.

## When NOT to use

- **Not a release.** For ad-hoc QA outside a release window, use AAASM-3198's
  full-production-validation pattern or a targeted `qa-*` agent directly, not
  this gate.
- **The sign-off already PASSes for this exact version and nothing changed
  since** — the artifact is the record; don't regenerate.
- **A security-only question.** Use `/release-security-gate` directly — this
  gate does not replace it, and a security-relevant behavioral finding
  discovered during QA is still classified per this gate's own protocol
  without editing the security sign-off.

## How to use

```text
/release-qa-gate <version>
```

`<version>` is the target literal exactly as it will appear in the tag (e.g.
`0.0.1-rc.7`, not `v0.0.1-rc.7`).

**Release-depth detection** mirrors `/release-security-gate`'s patch/minor/
major tiers, applied to QA depth per the release QA policy: patch = P0 +
changed/impacted surfaces; RC/minor = patch + relevant P1 + config matrix +
SDK interop + changed trust boundaries; major = RC/minor + broad P1/P2 +
full adversarial pass + docs/examples/design audit.

## The eight-step run procedure (summary — detail in REFERENCE.md)

1. **Manifest** — run `scripts/qa/build-verification-manifest.sh` once.
   Discovers canonical default branch, HEAD, baseline (qa-signoff -> deep-
   sweep-epic -> released-tag -> unknown), delta, CI state.
2. **Feature delta discovery** — run `scripts/qa/build-feature-delta.py`
   once. Cross-checks Jira ticket status against merged PRs and candidate-
   HEAD ancestry to classify every candidate ticket `RELEASE_ELIGIBLE` or
   `OUT_OF_CURRENT_RELEASE_QA_SCOPE` — see
   [Feature delta discovery](../../../docs/src/qa/release-qa-policy.md#feature-delta-discovery)
   for the eligibility rules and anti-circularity rule.
3. **Risk mapping** — run `scripts/qa/map-risk.py --manifest
   .qa/verification-manifest.json`. Produces overall risk, required lanes,
   and the journey set (always including the full P0 set from
   `qa/golden-journeys.yaml`).
4. **Depth/scope selection** — apply the release QA policy's tier rules to
   the risk-mapper output to get the final journey/lane list for this run's
   depth.
5. **Bounded parallel verification** — launch up to 10 `qa-*` sub-agents (see
   `qa/ORCHESTRATION.md`), each scoped to a manifest/journey slice, each
   returning the AAASM-5828 compact result schema.
6. **Finding verification** — for each `SUSPECTED_FINDINGS` entry, run the
   AAASM-5827 protocol (dedup -> independent verification by
   `qa-finding-verifier` for High/Critical/P0 -> confirm/reject).
7. **Jira filing and remediation** — confirmed defects only, in the project's
   Bug structure. Ordinary confirmed defects are then remediated within the
   same campaign via the autonomous remediation loop in
   `qa/FINDING-VERIFICATION-PROTOCOL.md` (implementation -> independent
   sub-agent review -> CI green -> admin merge -> post-merge reproduction),
   with human escalation reserved for that protocol's bounded carve-out
   list. QA-infrastructure-only defects (bugs in this gate's own
   scripts/skills) are fixed directly instead of filed — see the protocol's
   stated exception.
8. **Sign-off** — write `docs/release/qa-signoff/v<version>.md` from the
   template, with an exact `Verdict: PASS` or `Verdict: BLOCK` line.

## BLOCK rule (mandatory coverage cannot be silently skipped)

Per the release QA policy: `Verdict: BLOCK` when any P0 journey or changed
HIGH-risk surface ends the run `UNTESTED_OR_BLOCKED` without an explicit
human waiver recorded in the sign-off, or when any release-blocking finding
(per the policy's BLOCK-condition list) is open. A truthful `Verdict: BLOCK`
because real coverage could not be completed is a **correct** outcome of
this gate, not a failure of it — never convert unresolved/unverified
coverage into an inferred PASS to make a run look clean.

## Pre-conditions

1. Target `<version>` provided; previous tag/baseline resolvable via the
   manifest.
2. Run from the `agent-assembly/` checkout (or a worktree) with `remote`
   fetched.
3. `gh`, `git`, `python3` (with `pyyaml`), `jq` available for the manifest/
   risk-mapper scripts.

## Closing the campaign (mandatory)

`qa/CLEANUP-PROTOCOL.md` (AAASM-5846) is a mandatory closing step of both
this gate's own run and any remediation loop it triggers, per
`qa/FINDING-VERIFICATION-PROTOCOL.md`: per-merge worktree/process teardown,
a real CI-waiting mechanism (never a passive "monitoring" claim), and the
campaign's final-completion bar (0 stale worktrees, 0 unnecessary background
processes, 0 leftover listeners/servers, 0 leftover temp folders). Apply it
before reporting the campaign complete, not only at the very end.

## What this skill does NOT do

- It does not cut the tag (`/release-tag-cut`).
- It does not replace or gate `/release-security-gate` — both sign-offs are
  independently required.
- It classifies, verifies, and files confirmed defects, and remediates
  ordinary ones within the same campaign via the closed-loop sequence in
  `qa/FINDING-VERIFICATION-PROTOCOL.md` — human escalation is reserved for
  that protocol's bounded carve-out list, not confirmed-defect fixing in
  general.
- It does not run every P1/P2 journey on every patch — depth is risk-based,
  per the release QA policy.

## Detailed references

- **Run procedure detail, worked example, troubleshooting** →
  [REFERENCE.md](REFERENCE.md)
- **Release relay** → [`release-tag-cut/SKILL.md`](../release-tag-cut/SKILL.md)
- **Security gate (independent, composed alongside this one)** →
  [`release-security-gate/SKILL.md`](../release-security-gate/SKILL.md)
- **Mandatory campaign closing step** →
  [`../../../qa/CLEANUP-PROTOCOL.md`](../../../qa/CLEANUP-PROTOCOL.md)
