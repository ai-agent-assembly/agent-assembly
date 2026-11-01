# ADR 0042: Publication-Pending Release Evidence (`CANDIDATE_VERIFIED`)

- Status: Accepted (founder decision recorded on AAASM-6419, binding)
- Date: 2026-11-01
- Ticket: AAASM-6419 (Epic AAASM-6159). Builds on Core ADR 0037; amends nothing in it.

## Context

The release-evidence gate (Core ADR 0037, `scripts/qa/check-release-evidence.py`)
knows one authorizing state per journey, `PASS`, plus a human-approved waiver.
Some release-blocking journeys (the `fidelity: published_artifact` ones, for
rc.8: J04, J08, J17, J53, J56, J59) contain checks that can only be run against
artifacts that exist after publication. Before publication they cannot be
`PASS`; the only existing way to let such a row through is a waiver, which says
"this check is excused", not "this check is still owed".

The founder decision for B1 is binding: no blanket waiver for those rows.
Separate each row into pre-publication candidate verification and the checks
that genuinely need published artifacts; record the latter as PENDING, never
PASS; prepare the post-publication checks and failure response for a later,
SHA-specific release approval.

## Decision

1. **A third per-journey state, `PUBLICATION_PENDING`, and a QA verdict token
   `CANDIDATE_VERIFIED`.** The token contains no `PASS` substring, so every
   existing `PASS` pattern (the readiness greps, the status-token rules) cannot
   match it by accident. The security sign-off has no pending state: its verdict
   stays exactly `PASS | BLOCK`, and `CANDIDATE_VERIFIED` there is a checker BLOCK.
2. **Pending is admitted only against a committed obligation record**
   (`docs/release/qa-signoff/v<version>.publication-obligations.json`) plus a
   new registry field `publication_checks: [{id, channel, summary}]`, valid only
   when `fidelity == published_artifact`. Per journey the obligation lists the
   already-verified `candidate_checks` (each `PASS`, pre-publication fidelity,
   evidence reference, artifact digests), the `pending_checks` (id, channel, why
   publication-only, command, expected result), `depends_on`, and a
   `failure_response` (proposed actions, who is notified, deadline). Pending
   check ids must equal the registry's `publication_checks` ids, so a pending
   check cannot be added, dropped or renamed without a registry change, and
   `publication_checks` is part of the per-journey registry digest (only when
   declared, so no existing digest changes) so editing it after evidence drifts R2.
3. **The checker never trusts the emitter.** `check-release-evidence.py` reads
   the registry entry and the obligation file from git at the tag target (never
   the working tree), requires the obligation to be byte-identical at the
   candidate commit, compares the evidence's embedded copy to it, takes fidelity
   and `publication_checks` from the registry, and recomputes the verdict from
   the journeys. The evidence `verdict` field and the QA `Verdict:` line must
   both equal the recomputed value. The obligation file lives under
   `docs/release/qa-signoff/`, which R1 already classifies EXECUTABLE after the
   candidate; the strict tag-guard allowlist is deliberately not widened.
4. **Pending is never PASS, and never authorizes anything.** The verdict is
   `PASS` only when no row is pending; `CANDIDATE_VERIFIED` when every row is
   resolved and at least one is pending; otherwise `BLOCK`. A valid
   pending-only record makes the checker exit **3**, not 0. Every consumer that
   requires exit 0 (`release.yml`'s `release-evidence-gate`, `release-tag-guard.sh`
   step 4) therefore keeps refusing with no workflow change.
   `release-readiness.sh` reports the state with its own line
   (`CANDIDATE_VERIFIED — N obligations pending (not PASS)`), fails check 14 on
   exit 3, and never prints "safe to tag" for it.
5. **A pending row cannot also be waived.** The emitter resolves pending plus an
   exception to `BLOCK`, and the checker rejects a hand-edited record that has
   both.
6. **A pending Result cell is never ambiguous.** The emitter refuses a cell that
   says `PUBLICATION_PENDING` and also names another state (`FAILED`, `BLOCKING`,
   `UNTESTED`, `PARTIAL`, ...). The checker blocks a row whose Result cell claims
   `PUBLICATION_PENDING` but whose status is anything else, and readiness check 12
   refuses `Verdict: PASS` over a pending row.

## Consequences

- A release can honestly be recorded as "candidate verified, N publication
  checks owed" without a waiver, and the owed checks, commands and failure
  response are committed and digest-bound before anything is published.
- `CANDIDATE_VERIFIED` does not authorize tagging or publishing. Authorizing a
  publish on a `CANDIDATE_VERIFIED` record is a separate owner decision
  (SHA-specific release approval) and needs a `release.yml` change that this ADR
  does not make.
- Recording post-publication results is not built here. Evidence is immutable
  (Core ADR 0037, R1b), so a post-publication result is a new evidence attempt,
  never an in-place edit of the pending record. Specifying that appender is
  follow-up work.
- Adding `publication_checks` to the real catalog entries and writing the real
  obligation files is a follow-up catalog change; this ADR's implementation only
  makes the state expressible and verifiable.

## Alternatives considered

- **Blanket waiver** for the six journeys: rejected by the founder; it records
  the check as excused and loses what is still owed.
- **Checker exit 0 for `CANDIDATE_VERIFIED`**: would let the unchanged
  `release.yml` gate publish a candidate with owed checks; rejected as unsafe.
- **Widening the tag-guard allowlist for the obligation file**: rejected; the
  obligation must be final at the candidate, so a later edit is an R1 BLOCK.
