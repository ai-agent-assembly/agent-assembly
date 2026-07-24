import type { BudgetThresholdBucket } from '../../components/topology/budgetThreshold'

/**
 * Burn bucket → solid status token, shared by the team budget card amount/bar
 * and the list-pane mini bar. Kept in its own module (not the card) so the card
 * file exports only its component (satisfies `react-refresh/only-export-components`).
 */
export function budgetBucketColor(bucket: BudgetThresholdBucket | null): string {
  if (bucket === 'danger') return 'var(--status-danger-solid)'
  if (bucket === 'warn') return 'var(--status-warning-solid)'
  return 'var(--status-success-solid)'
}
