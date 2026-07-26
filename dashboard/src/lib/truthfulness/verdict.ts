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
 * `Allow` and the grid paints a fully-permissive green wall while the gateway
 * is in fact denying those calls.
 *
 * This is a **display-only** defect. `decide` is private to `aa-api` and no
 * enforcement crate depends on `aa-api`, so nothing here is a runtime bypass —
 * the enforcement path is untouched. What is wrong is the *claim the UI makes*.
 *
 * ── The rule ────────────────────────────────────────────────────────────────
 *
 * **Never infer permission from missing policy data.** An empty or unavailable
 * cascade must render as Unconfigured / Not evaluated, never as a green Allow.
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

/**
 * Tally the verdicts of a cell collection.
 *
 * When the cascade is absent, the absence propagates to every count. When it is
 * present but empty, every count is `unconfigured` — including `deny`, because
 * a cascade that loaded nothing evaluated nothing, so a zero denial count is a
 * claim the data cannot support.
 */
export function tallyVerdicts(
  decisions: Iterable<CapabilityVerdict | undefined>,
  cascade: Certain<CascadeEvidence>,
): VerdictTally {
  if (!isKnown(cascade)) {
    return {
      allow: propagateAbsence(cascade),
      narrow: propagateAbsence(cascade),
      deny: propagateAbsence(cascade),
    }
  }
  if (cascadeIsEmpty(cascade.value)) {
    const reason = 'No policy document is loaded, so no cell was evaluated'
    return {
      allow: absent('unconfigured', reason),
      narrow: absent('unconfigured', reason),
      deny: absent('unconfigured', reason),
    }
  }

  let allow = 0
  let narrow = 0
  let deny = 0
  for (const decision of decisions) {
    if (decision === 'allow') allow += 1
    else if (decision === 'narrow') narrow += 1
    else if (decision === 'deny') deny += 1
  }
  return { allow: known(allow), narrow: known(narrow), deny: known(deny) }
}
