# Finding-verification protocol demonstration (AAASM-5827 AC)

Walks one true finding and one false/duplicate candidate through the
protocol in `qa/FINDING-VERIFICATION-PROTOCOL.md`.

## Case 1 — true finding (real, from this Epic's own work)

This is a real finding surfaced during this Epic's implementation, not a
constructed example — see AAASM-5829 (PR #2125).

- **SUSPECTED**: while self-reviewing `scripts/qa/map-risk.py`, its
  `matches()` function was found to only check `path.startswith(pattern)`.
  Suspected impact: a HIGH-risk rule (e.g. `aa-gateway/src/policy/`) could
  silently resolve to a shallower MEDIUM rule when fed a truncated surface —
  exactly what AAASM-5825's manifest generator produces
  (`affected_surfaces` truncated to two path segments).
- **DEDUPED**: checked — no existing Bug or prior-sweep finding covers this
  (the code was written in this same session; nothing to duplicate against).
- **INDEPENDENTLY_VERIFIED**: reproduced directly — ran
  `map-risk.py aa-gateway/src` before the fix (returned `MEDIUM`) and
  confirmed the expected `HIGH` after adding the `pattern.startswith(path)`
  check, plus an end-to-end `--manifest` run with a truncated surface. This
  is a Medium-severity finding in QA-gate infrastructure (not a product
  surface), so coordinator-level verification (rather than a dedicated
  `qa-finding-verifier` instance) was sufficient per the protocol's Medium
  tier.
- **CONFIRMED**.
- **FILED**: **not filed as a Jira Bug** — per the protocol's stated
  exception, a defect in the QA gate's own infrastructure (built in this same
  Epic, not yet merged) is fixed directly in the same PR rather than filed as
  a product defect. The fix and the before/after evidence are committed in
  AAASM-5829's PR #2125 commit `dacec521e`.

This demonstrates the full `SUSPECTED -> DEDUPED -> INDEPENDENTLY_VERIFIED ->
CONFIRMED` path, landing on the "fix directly, don't file" branch that
applies specifically to this Epic's own tooling.

## Case 2 — false/duplicate candidate (illustrative)

Illustrative only — no Bug is filed or claimed to exist for this case; it
demonstrates the REJECTED/DEDUPED branches structurally.

- **SUSPECTED**: a hypothetical `qa-functional` worker reports "`aasm status`
  returns exit code 1 when no gateway is reachable" as a suspected defect.
- **DEDUPED**: the coordinator checks existing Bugs/known-limitations first
  and finds this is **documented, expected behavior** (`aasm status` against
  an unreachable gateway is supposed to fail with a non-zero exit — that's
  the CLI correctly reporting an unreachable dependency, not a defect). This
  is caught at the dedup/known-limitation check, before a verifier slot is
  even spent.
- **Outcome**: `REJECTED` — not filed, not linked to an existing Bug (there
  isn't one), recorded compactly (if at all) as a non-finding in the run's
  internal notes. No Jira noise created.

This demonstrates that the protocol's dedup/known-limitation check — not
just independent reproduction — is a real gate that can reject a candidate
before it ever reaches `qa-finding-verifier`, which is the cheaper failure
mode (a worker's plausible-sounding but actually-expected observation costs
a dedup check, not a whole verifier slot).

## What this proves

- A worker's `SUSPECTED_FINDINGS` entry is never automatically a Bug (Case 2
  never becomes one).
- A real, independently-reproduced finding (Case 1) went through dedup and
  independent verification before any filing decision — and the filing
  decision correctly routed to "fix directly" rather than "open a product
  Bug," because the protocol's exception for this Epic's own infrastructure
  applied.
- Both branches are demonstrated without fabricating a fake product Bug
  merely to exercise the FILED state — the actually-representative outcome
  for QA-gate-infrastructure findings during this Epic's own build-out is
  "fix directly," and pretending otherwise would misrepresent the protocol.
