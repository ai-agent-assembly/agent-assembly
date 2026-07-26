import { bucketForBudget } from '../topology/budgetThreshold'
import './BudgetBar.css'

export interface BudgetBarProps {
  /**
   * Amount spent in USD, or `null` when no figure is available (AAASM-5127).
   *
   * Nullable because the org monthly figure is: `/api/v1/costs` only ever
   * carries `monthly_spend_usd` once a monthly limit is configured — the
   * gateway seeds `monthly_spent_usd` behind a `has_monthly` gate
   * (`aa-gateway/src/budget/tracker.rs`) — and the field is absent, not zero,
   * until then. The caller used to pass `spend ?? 0`, which drew a bar
   * measuring a month of spend nobody ever recorded.
   */
  readonly used: number | null
  /**
   * Configured limit in USD, or `null` when none is configured.
   *
   * `null` is not `0`. A configured `$0` ceiling is a real fact — the gateway
   * denies on `spent >= limit`, so any spend at all has already reached it —
   * whereas an absent one means no ceiling was ever set and there is no burn
   * ratio to report.
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
 *
 * A burn ratio needs *both* numbers. Missing either leaves the bar unmeasured:
 * no fill, no threshold bucket, and an `aria-label` that says the burn is
 * unknown. It previously fell back to `bucket='ok'` at `0%`, which painted an
 * unmeasured budget the same green as a comfortably-underspent one and
 * announced "0%" — a positive claim of headroom on evidence that does not
 * exist (AAASM-5127). A zero-width fill is still a rendered measurement of
 * zero, so none is drawn.
 *
 * `bucketForBudget` maps `limit <= 0` to `ok`, which is the same false-green
 * for the *configured* `$0` ceiling: it is fully consumed, not untouched. The
 * bar resolves that case itself rather than reaching into the shared threshold
 * helper, which topology's node-detail panel also depends on.
 */
export function BudgetBar({ used, limit, label }: BudgetBarProps) {
  const measurable = used !== null && limit !== null
  const exhausted = measurable && limit <= 0
  const pct = !measurable ? null : exhausted ? 100 : Math.min(100, (used / limit) * 100)
  let bucket: string | undefined
  if (measurable) bucket = exhausted ? 'danger' : bucketForBudget(used, limit)

  let truthState: string | undefined
  if (used === null) truthState = 'unknown'
  else if (limit === null) truthState = 'unconfigured'

  return (
    <div
      className="costs-budget-bar"
      data-testid="costs-budget-bar"
      data-threshold-bucket={bucket}
      data-truth-state={truthState}
      aria-label={
        pct === null
          ? `${label} unknown — ${used === null ? 'no spend figure is available' : 'no limit is configured'}`
          : `${label} ${Math.round(pct)}%`
      }
    >
      {pct !== null && (
        <div
          className="costs-budget-bar__fill"
          style={{ width: `${pct}%` }}
          data-threshold-bucket={bucket}
        />
      )}
    </div>
  )
}
