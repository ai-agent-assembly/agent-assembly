# references/defect-lifecycle.md — product-validation

## The mandatory rule

**A reproducible material defect found by any validation track becomes a
real Jira Bug.** Not a bullet point in a report, not a comment, not a
TODO — a tracked issue with the fields below, so it survives past the
session that found it and shows up in normal backlog/triage flow. A
"known limitations" section in a quality report is for defects that have
already gone through this lifecycle and were explicitly deferred or
accepted, never a way to record a defect without filing it.

"Material" means: it would affect a real user's ability to complete the
scenario, contradicts documented behavior, or represents a fail-open/
silent-failure condition. A cosmetic nit that doesn't change what the
product does is judgment-call territory — record it in the report either
way, but filing every wording quibble as a Bug is its own failure mode
(noise that drowns real defects). When genuinely unsure, file it; a Bug
that turns out minor gets closed as Won't Fix, which costs far less than
a real defect that was never tracked.

## Required fields on the Bug

| Field | Content |
|---|---|
| Problem | One or two sentences: what's wrong, stated as an observation, not a fix. |
| Affected scope | Which scenario/track/persona hit it; which component/feature it belongs to. |
| Severity | Critical / High / Medium / Low — judged by user impact, not by how hard it is to fix. A total, 100%-reproducible break of documented behavior is Critical regardless of how small the code change to fix it turns out to be. |
| Environment | OS, runtime version, deployment shape, commit/version tested — enough for someone else to reproduce without guessing. |
| Repro | The literal steps, ideally copy-pasted from the scenario's `actions` field. |
| Expected vs. actual | What the docs/spec/scenario said should happen, and what actually happened — verbatim output where possible, not a paraphrase. |
| Impact | What breaks for a real user if this ships as-is. |
| Evidence | Link/reference to the captured evidence (log excerpt, screenshot, command output) — see `quality-report-template.md` for where raw evidence lives. |

## The lifecycle

```
found (scenario FAILs) -> filed as Jira Bug -> linked to the scenario/report
   -> fixed (normal engineering-loop cycle: Narrow -> Validate -> Full Gate)
   -> scenario rerun through the ORIGINAL scenario, not a narrower check
   -> PASS evidence captured
   -> Bug resolved, linked to the fix commit/PR
```

or, explicitly:

```
found -> filed as Jira Bug -> triaged as deferred / accepted-known-limitation
   -> rationale recorded on the Bug and in the quality report
   -> Bug stays open (deferred) or is closed with the accepted-limitation
      rationale attached — never silently dropped
```

Rerunning through the *original* scenario matters: a narrower regression
test proves the specific code path is fixed, but only rerunning the full
scenario that first found the defect proves the user-facing journey now
actually works — the same "re-run the failed journey after every fix,
not just unit tests" discipline circinus's HORO-406 report names
explicitly in its "Summary of fixes shipped in this PR" section, where
every fix commit lists an independent rerun result against a fresh clone,
separate from that fix's own unit test.

## Deferred vs. accepted-known-limitation — the honest split

Not every filed Bug gets fixed in the same session or even the same
release. Two legitimate non-fix outcomes, both requiring explicit
rationale — silently doing nothing is not one of the options:

- **Deferred**: real defect, not fixed now, tracked for later. State why
  (scope, priority, dependency on other work) and keep the Bug open,
  linked from the quality report's "known limitations" section.
- **Accepted as a known limitation**: a considered decision that the
  current behavior is acceptable as-is (e.g. it fails safe, not open; the
  cost of fixing exceeds the actual impact). State the rationale on the
  Bug itself, not only in the report — a rationale that lives only in a
  report is invisible to anyone who later finds the same Bug in Jira.

Real worked example of exactly this split, from circinus's HORO-406
report (`docs/hardening/HORO-406-fresh-user-dogfood-report.md`):

- **Filed and left open, deferred**: HORO-436 (`circinus explain`'s
  BLOCK/ALLOW headline drops shadow-mode framing — "needs a product
  decision on explain's headline format"), HORO-437 (undocumented
  global-per-machine state directory), HORO-438
  (`CIRCINUS_ANALYSIS_SEND_CONTENT` silently treated as false on a
  malformed value).
- **Explicitly accepted, not filed, with stated rationale** — this is the
  honest alternative to filing everything: `circinus hook --help`'s
  inconsistent usage-line behavior was "Accepted as minor friction, not
  filed — inconsistent but each subcommand's own usage text still prints
  on the unrecognized-verb path," and `circinus doctor`'s reassuring
  summary wording was "Accepted as minor friction, not filed —
  individual WARN/N/A lines are clear and accurate; only the one-line
  summary phrasing is slightly reassuring-sounding." Both state the
  reasoning inline rather than just omitting the finding.
- **Fixed and reverified in the same session**: e.g. the schema-migration
  race (`027edba`) and the `uninstall` path bug (`df7aa98`) — both
  Critical, both re-verified against a fresh clone/stress test after the
  fix landed, per the lifecycle above.

## Never do this

- Never silently lower a scenario's pass bar (loosen an assertion, skip a
  step, narrow the check) to make a gate read green. If a scenario can't
  pass as originally scoped, that's a FAIL or BLOCKED result plus a filed
  Bug — not a quietly rewritten scenario.
- Never report a defect only in prose without filing it. Prose-only
  findings don't survive the session and don't enter normal triage.
- Never treat "accepted as known limitation" as a way to avoid filing —
  the acceptance decision still needs a Bug (or an explicit rationale
  attached to one) to be discoverable later, except for the narrow case
  of genuinely trivial cosmetic items judged not material (see above) —
  and even those get recorded in the quality report, just not as a Bug.
