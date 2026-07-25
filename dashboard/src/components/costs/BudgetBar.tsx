import { bucketForBudget } from '../topology/budgetThreshold'
import './BudgetBar.css'

export interface BudgetBarProps {
  /** Amount spent, in USD. */
  readonly used: number
  /**
   * Configured limit, in USD. `null`/`0` renders an empty track (no burn) — the
   * OSS cost summary omits limits when none is configured, and the caller passes
   * that through rather than fabricating a denominator.
   */
  readonly limit: number | null
  /** Accessible label for the bar (e.g. `"daily budget burn"`). */
  readonly label: string
}

/**
 * Thin budget-burn bar for the Costs KPI cards, mirroring the `BudgetBar` in
 * `design/v1/hi-fi/costs.jsx`. The fill colour comes from the shared
 * `bucketForBudget` threshold (green <80 / amber 80–95 / red ≥95) so it matches
 * `TeamBudgetBar` and the budget tree; width is clamped to 100% so an
 * over-budget period pins the bar full rather than overflowing its track.
 */
export function BudgetBar({ used, limit, label }: BudgetBarProps) {
  const hasLimit = limit != null && limit > 0
  const pct = hasLimit ? Math.min(100, (used / limit) * 100) : 0
  const bucket = hasLimit ? bucketForBudget(used, limit) : 'ok'
  return (
    <div
      className="costs-budget-bar"
      data-testid="costs-budget-bar"
      data-threshold-bucket={bucket}
      aria-label={`${label} ${Math.round(pct)}%`}
    >
      <div
        className="costs-budget-bar__fill"
        style={{ width: `${pct}%` }}
        data-threshold-bucket={bucket}
      />
    </div>
  )
}
