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
 * Burn percentage against a *configured* ceiling, `$0` included.
 *
 * A configured `$0` ceiling is fully consumed at any spend, including none: the
 * gateway denies on `spent >= limit`, so `0 >= 0` already blocks. It therefore
 * reads 100%, not the `0%` a `limit > 0` guard falls back to — `0%` is a claim
 * of untouched headroom against a budget that permits nothing.
 *
 * Clamped to 100 so an over-budget period pins its bar full rather than
 * overflowing the track.
 */
export function burnPercentForConfiguredBudget(spent: number, limit: number): number {
  if (limit <= 0) return 100
  return Math.min(100, (spent / limit) * 100)
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
