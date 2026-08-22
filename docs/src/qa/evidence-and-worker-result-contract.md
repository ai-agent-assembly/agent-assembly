# QA evidence contract and worker result schema

> Reusable contract consumed by `/release-qa-gate` (AAASM-5821), the reusable
> QA sub-agents (AAASM-5826) and the independent finding-verification protocol
> (AAASM-5827), and used when writing the [QA sign-off](../../release/qa-signoff/TEMPLATE.md).
> Defines **what counts as sufficient evidence** per surface and **the compact
> shape** every worker returns, so parallelism saves tokens instead of just
> multiplying investigation transcripts.

## Why this exists

Parallel QA workers only save context if each one returns a small, comparable
result instead of a full investigation transcript. This page is the one place
that defines "enough evidence" per surface and the one result shape every
worker — and the coordinator aggregating them — can rely on without
re-negotiating format per run.

## Evidence contract, by surface

Minimum useful evidence per verification type. A worker that cannot produce
this minimum reports `BLOCKED`, it does not pad the report to look complete.

### CLI / command behavior

- Command/action invoked (exact, reproducible).
- Tested version/SHA.
- Exit status, where relevant.
- Meaningful stdout/stderr observation (the line(s) that matter, not the full
  output).
- Expected vs. actual.

### HTTP / gRPC / API behavior

- Request/action made.
- Relevant response/status/effect observed.
- Expected vs. actual.
- Tested endpoint/version.

### Browser / Design QA

- URL/view exercised.
- User action taken.
- Observed result.
- Console/network failure status (present/absent — not a full log dump).
- A screenshot only when it materially supports the finding or sign-off
  (design regressions, visual defects) — not by default.

### Documentation contract QA

- The documented claim/command being checked.
- The actual product behavior or authoritative contract it was checked
  against.
- Result/drift classification (matches / drifted / stale).

### Security-relevant behavior

- Precondition (what state/access the check assumed).
- Attack/action performed.
- Observed boundary behavior.
- Exploitability/impact assessment.
- Whether independent verification is required (see AAASM-5827 — High/Critical
  always requires it).

### Reliability / failure-path QA

- Induced or reachable failure condition.
- Recovery/degradation behavior observed.
- Diagnostics/observability available during the failure.
- Expected vs. actual.

## Worker result schema

Every QA worker returns exactly these sections — nothing else:

```text
STATUS: COMPLETE | PARTIAL | BLOCKED
BASELINE: <repo/surface> @ <SHA or version>
VERIFIED:
  - <concise PASS/FAIL check, one line each>
SUSPECTED_FINDINGS:
  - id: <F-n>
    severity: Critical | High | Medium | Low
    surface: <affected path/component>
    expected: <one line>
    actual: <one line>
    evidence: <reproduction steps or reference — per the evidence contract above>
    confidence: HIGH | MEDIUM | LOW
UNTESTED_OR_BLOCKED:
  - <surface/journey> — <reason>
CONFIDENCE: HIGH | MEDIUM | LOW
```

Rules:

- No chain-of-thought, no investigation narrative, no file-by-file summary.
- No large copied logs — cite a path/line/command instead of pasting output.
- A worker may cite implementation source for **diagnosis**, but an outside-in
  journey's PASS/FAIL still rests on observed behavior where the journey
  contract requires it (see the release QA policy's outside-in-is-authoritative
  principle) — reading the source that *should* handle a case is not evidence
  the running product handles it.
- `UNTESTED_OR_BLOCKED` is always preferable to an inferred PASS. Do not mark
  something PASS because it looks like it should work.
- Stop investigating once there is sufficient evidence for the property (PASS)
  or the defect (FAIL) — do not keep gathering evidence past that point.

## Evidence for independent verification (High/Critical)

A `SUSPECTED_FINDINGS` entry with `severity: High` or `Critical` must carry
enough detail (exact reproduction, exact command/request, exact expected vs.
actual) that a **different** agent can reproduce it independently without
inheriting the first agent's reasoning — see AAASM-5827. A finding whose
evidence is "I believe X because the code does Y" without an observed
behavioral reproduction is not sufficient for High/Critical; it downgrades to
`UNTESTED_OR_BLOCKED` with a note, or the worker escalates for direct
verification before reporting it as a finding.

## Worked example

Three entries showing the schema handles a clean PASS, a suspected defect, and
an explicitly untested item in one compact result:

```text
STATUS: PARTIAL
BASELINE: ai-agent-assembly/agent-assembly @ 1f322d59af8750e40caa1d0a612b6948f9bf59f0
VERIFIED:
  - `aasm topology` against a live gateway returns the registered agent — PASS
  - `aasm policy show` reflects a just-applied policy change — PASS
SUSPECTED_FINDINGS:
  - id: F-1
    severity: Medium
    surface: aa-cli/src/commands/policy
    expected: "aasm policy apply --dry-run prints a diff and exits 0 without applying"
    actual: "exits 0 but the policy was actually applied (verified via aasm policy show before/after)"
    evidence: "ran `aasm policy apply --dry-run policy.yaml`, then `aasm policy show` — new rule present"
    confidence: HIGH
UNTESTED_OR_BLOCKED:
  - "aa-proxy CA install on Windows — no Windows test environment available this run"
CONFIDENCE: MEDIUM
```

This is deliberately short: a coordinator aggregating 5 of these in parallel
gets three clear checks, one actionable finding with enough detail to hand to
an independent verifier, and one honestly-scoped gap — not five essays.

## Non-goals

- This page does not define the Bug ticket format — that is AAASM-5827.
- It does not stand up a test-report database or UI — the result lives only in
  the coordinator's context for one run and the compact rows it contributes to
  the QA sign-off.
- It does not mandate screenshots/logs by default — only when they materially
  improve reproducibility.
