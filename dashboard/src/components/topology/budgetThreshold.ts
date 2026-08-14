/**
 * Budget burn → threshold bucket mapping.
 *
 * Shared between TeamBudgetBar (AAASM-1339) and the node-detail panel
 * progress bar (AAASM-1337). Same thresholds:
 *   - `ok`     ratio  < 0.80
 *   - `warn`   0.80 ≤ ratio < 0.95
 *   - `danger` ratio ≥ 0.95
 *
 * Extracted into its own module so TeamBudgetBar.tsx exports only the
 * component (satisfies `react-refresh/only-export-components`).
 */

export type BudgetThresholdBucket = 'ok' | 'warn' | 'danger'

/** Map a precomputed burn ratio (spent/limit) to its threshold bucket. */
export function bucketForRatio(ratio: number): BudgetThresholdBucket {
  if (ratio < 0.8) return 'ok'
  if (ratio < 0.95) return 'warn'
  return 'danger'
}

export function bucketForBudget(spent: number, limit: number): BudgetThresholdBucket {
  if (limit <= 0) return 'ok'
  return bucketForRatio(spent / limit)
}

/**
 * Utilisation percentage against a *configured* ceiling, `$0` included.
 *
 * A configured `$0` ceiling is fully consumed at any spend, including none: the
 * gateway denies on `spent >= limit`, so `0 >= 0` already blocks. It therefore
 * reads 100, not the `null`/`0` that a `limit > 0` guard falls back to — both
 * of which claim untouched headroom against a budget permitting nothing.
 *
 * 100 rather than infinity: the ratio is genuinely undefined at a zero divisor,
 * so "fully consumed" is the strongest thing that can honestly be said. It is a
 * floor — a `$0` ceiling with spend against it is *at least* exhausted.
 *
 * **Unclamped above zero**, so a genuinely over-budget period reads its real
 * `105.0%` rather than being flattened to 100 and reported as merely
 * exhausted. Use `burnPercentForConfiguredBudget` for bar widths, which need
 * the clamp.
 */
export function utilisationPercentForConfiguredBudget(spent: number, limit: number): number {
  if (limit <= 0) return 100
  return (spent / limit) * 100
}

/**
 * Burn percentage for a bar *width* — `utilisationPercentForConfiguredBudget`
 * clamped to 100, so an over-budget period pins its track full rather than
 * overflowing it.
 */
export function burnPercentForConfiguredBudget(spent: number, limit: number): number {
  return Math.min(100, utilisationPercentForConfiguredBudget(spent, limit))
}

/**
 * Threshold bucket for a *configured* ceiling, `$0` included.
 *
 * Deliberately separate from `bucketForBudget`, which must keep mapping
 * `limit <= 0` to `ok`: topology's node-detail panel and `TeamListPane` reach
 * the thresholds through `bucketForRatio` on ratios that are already
 * normalised, where a non-positive divisor is not a configured ceiling but a
 * missing one. Changing the shared mapping to suit the spend surfaces would
 * repaint those.
 *
 * This is the one rule every Costs surface reads, so a single team row cannot
 * report `danger` in its spend cell and `ok` in the burn bar beside it — the
 * three-way disagreement AAASM-5185 found, and the same false green AAASM-5127
 * removed from `BudgetBar`.
 */
export function bucketForConfiguredBudget(spent: number, limit: number): BudgetThresholdBucket {
  if (limit <= 0) return 'danger'
  return bucketForRatio(spent / limit)
}
