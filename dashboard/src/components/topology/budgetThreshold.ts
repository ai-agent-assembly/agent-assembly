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

export function bucketForBudget(spent: number, limit: number): BudgetThresholdBucket {
  if (limit <= 0) return 'ok'
  const ratio = spent / limit
  if (ratio < 0.8) return 'ok'
  if (ratio < 0.95) return 'warn'
  return 'danger'
}
