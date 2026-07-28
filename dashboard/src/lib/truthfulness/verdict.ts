/**
 * Shared capability-verdict semantics (AAASM-5173).
 *
 * Defines, once, what a verdict cell may claim and what an *absent* verdict
 * means — so no page-level lane re-derives it and lands on a different answer.
 *
 * ── Why this module has to exist ────────────────────────────────────────────
 *
 * `aa-api`'s matrix projection resolves each cell with `decide()`
 * (`aa-api/src/routes/capability.rs:480`), whose final arm is:
 *
 *     Decision::Allow   // "Anything else is allowed because no capability
 *                       //  rule constrains it."
 *
 * `Allow` is therefore the *fallback*, not a measurement. Under AAASM-5106 the
 * policy cascade is empty in every shipped deployment, so `caps.deny` is empty
 * and `allow_is_restricted()` is false — which means every cell resolves to
 * `Allow`: the grid asserts `allow` for every capability, an unbroken wall of
 * `ALLOW`, while the gateway is in fact denying those calls.
 *
 * This is a **display-only** defect, and specifically a *data* one rather than a
 * logic one. `decide` is a line-for-line mirror of the gateway's
 * `stage_capability` (`aa-gateway/src/engine/decision.rs:207-221`) — same deny
 * check, same fail-closed `allow_is_restricted()` — so it is not drifting from
 * enforcement; it is being handed a cascade nothing populated. It is also
 * private to `aa-api`, which no enforcement crate depends on, so nothing here
 * is a runtime bypass. What is wrong is the *claim the UI makes*.
 *
 * ── The rule ────────────────────────────────────────────────────────────────
 *
 * **Never infer permission from missing policy data.** An empty or unavailable
 * cascade must render as Unconfigured / Not evaluated, never as an asserted
 * Allow.
 * `resolveVerdict` is the single implementation of that rule, and
 * `verdict.test.ts` guards it.
 */

import { absent, isKnown, known, propagateAbsence, type Certain } from './absence'

/**
 * The verdicts a cell may carry, mirroring `aa_api::models::capability::Decision`.
 * `na` is the backend's "this verb has no meaning for this resource" marker.
 */
export type CapabilityVerdict = 'allow' | 'narrow' | 'approval' | 'deny' | 'na'

/**
 * What the dashboard knows about the policy cascade a verdict was drawn from.
 *
 * `documentCount` is the number of policy documents the gateway actually
 * resolved into the cascade. Zero is the AAASM-5106 condition: the projection
 * still emits a decision for every cell, but no rule participated in producing
 * it, so the decision carries no authority.
 */
export interface CascadeEvidence {
  readonly documentCount: number
}

/** Whether a cascade actually constrained anything. */
export function cascadeIsEmpty(evidence: CascadeEvidence): boolean {
  return evidence.documentCount <= 0
}

/**
 * Resolve one matrix cell into either a verdict the dashboard may assert, or an
 * explicit absence.
 *
 * Precedence, strongest disqualifier first:
 *
 *  1. **Cascade absent** — the matrix request failed or is still in flight. No
 *     verdict is trustworthy, not even a `deny`, so the cascade's own absence
 *     propagates unchanged.
 *  2. **No decision** — the cell is missing from the payload entirely. Nothing
 *     evaluated it, so it is `not-evaluated`, never a default `allow`.
 *  3. **`na`** — the backend models no such verb for this resource. That is a
 *     permanent, honest gap: `not-supported`.
 *  4. **`allow` on an empty cascade** — the AAASM-5106 case. `allow` is
 *     `decide()`'s fallback, so with no policy documents it means "nothing
 *     constrained this", which is *absence of evaluation*, not permission. It
 *     renders `unconfigured`.
 *  5. Anything else is a real, rule-backed verdict.
 *
 * Step 4 is deliberately narrow. A `deny` / `narrow` / `approval` is a positive
 * restriction and survives an empty cascade untouched — folding those to an
 * absence would *weaken* what the operator sees, which is the opposite failure.
 * Only the permissive fallback is disqualified.
 */
export function resolveVerdict(
  decision: CapabilityVerdict | undefined,
  cascade: Certain<CascadeEvidence>,
): Certain<CapabilityVerdict> {
  if (!isKnown(cascade)) {
    return propagateAbsence(cascade)
  }
  if (decision === undefined) {
    return absent('not-evaluated', 'No decision was projected for this cell')
  }
  if (decision === 'na') {
    return absent('not-supported', 'This verb has no meaning for this resource')
  }
  if (decision === 'allow' && cascadeIsEmpty(cascade.value)) {
    return absent('unconfigured', 'No policy document is loaded, so nothing granted this')
  }
  return known(decision)
}

/**
 * Aggregate verdict counts for a summary row.
 *
 * Every field is `Certain` because a count is exactly the number most easily
 * faked: "0 denied" reads as *we checked and found no denials*, which is a very
 * different statement from *we never checked*. On an absent or empty cascade
 * all three counts are absences, not zeroes.
 */
export interface VerdictTally {
  readonly allow: Certain<number>
  readonly narrow: Certain<number>
  readonly deny: Certain<number>
}

/** Every count carries the same absence, for the cases that disqualify a tally. */
function tallyOf(allow: Certain<number>, narrow: Certain<number>, deny: Certain<number>): VerdictTally {
  return { allow, narrow, deny }
}

/**
 * Tally the verdicts of a cell collection.
 *
 * **Every cell is resolved through [`resolveVerdict`]** rather than inspected
 * directly, so the two entry points into this module cannot answer the same
 * input differently. An earlier revision duplicated the classification here and
 * promptly drifted: `resolveVerdict(undefined, loaded)` said `not-evaluated`
 * while the tally counted the same cell as a measured zero.
 *
 * Three things disqualify the whole tally rather than merely going uncounted:
 *
 *  - an **absent cascade**, whose absence propagates to every count;
 *  - an **empty cascade**, where nothing was evaluated, so every count is
 *    `unconfigured` — including `deny`, since a zero denial count over an
 *    unevaluated grid is a claim the data cannot support;
 *  - **any unevaluated cell** (`not-evaluated`). A count is only a measurement
 *    if it covers the whole set it claims to describe; "0 denied" over a grid
 *    with holes in it is the same lie in a smaller font.
 *
 * `not-supported` (`na`) does *not* disqualify: it is a permanent, honest
 * statement that the verb has no meaning for that resource, so the cell is
 * legitimately outside the population being counted.
 */
export function tallyVerdicts(
  decisions: Iterable<CapabilityVerdict | undefined>,
  cascade: Certain<CascadeEvidence>,
): VerdictTally {
  if (!isKnown(cascade)) {
    return tallyOf(propagateAbsence(cascade), propagateAbsence(cascade), propagateAbsence(cascade))
  }
  if (cascadeIsEmpty(cascade.value)) {
    const reason = 'No policy document is loaded, so no cell was evaluated'
    return tallyOf(
      absent('unconfigured', reason),
      absent('unconfigured', reason),
      absent('unconfigured', reason),
    )
  }

  // Inline closed 3-member literal union, tallied client-side — narrow-union
  // Record gap (AAASM-5245 gap 2).
  // eslint-disable-next-line no-restricted-syntax
  const counts: Record<'allow' | 'narrow' | 'deny', number> = { allow: 0, narrow: 0, deny: 0 }
  for (const decision of decisions) {
    const resolved = resolveVerdict(decision, cascade)
    if (isKnown(resolved)) {
      if (resolved.value in counts) counts[resolved.value as keyof typeof counts] += 1
      continue
    }
    // A permanent, honest gap is outside the population being counted; any
    // other absence means the grid has a hole and no count over it is a
    // measurement.
    if (resolved.state === 'not-supported') continue
    const reason = 'At least one cell in this grid was never evaluated'
    return tallyOf(
      absent(resolved.state, reason),
      absent(resolved.state, reason),
      absent(resolved.state, reason),
    )
  }
  return tallyOf(known(counts.allow), known(counts.narrow), known(counts.deny))
}
