import './TeamBudgetBar.css'

export type BudgetThresholdBucket = 'ok' | 'warn' | 'danger'

export function bucketForBudget(spent: number, limit: number): BudgetThresholdBucket {
  if (limit <= 0) return 'ok'
  const ratio = spent / limit
  if (ratio < 0.8) return 'ok'
  if (ratio < 0.95) return 'warn'
  return 'danger'
}

export interface TeamBudgetBarProps {
  readonly team: string
  readonly spent: number
  readonly limit: number
}

/**
 * Team-level budget bar shown above each topology team cluster (AAASM-1339).
 * Threshold buckets:
 *   - `ok`     ratio  < 0.80   → `--ok`
 *   - `warn`   0.80 ≤ ratio < 0.95 → `--warn`
 *   - `danger` ratio ≥ 0.95   → `--danger`
 *
 * Same threshold contract as the AAASM-1337 node-detail-panel progress bar
 * (`bucketForBudget` is the shared source of truth).
 */
export function TeamBudgetBar({ team, spent, limit }: TeamBudgetBarProps) {
  const bucket = bucketForBudget(spent, limit)
  const ratio = limit > 0 ? Math.min(1, spent / limit) : 0
  const percent = Math.round(ratio * 100)

  return (
    <div
      className="team-budget-bar"
      data-testid="team-budget-bar"
      data-team={team}
      data-threshold-bucket={bucket}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={percent}
      aria-label={`${team} budget burn ${percent}%`}
    >
      <div className="team-budget-bar__head">
        <span className="team-budget-bar__team">{team}</span>
        <span className="team-budget-bar__amount">
          ${spent.toFixed(0)} / ${limit.toFixed(0)} · {percent}%
        </span>
      </div>
      <div className="team-budget-bar__track">
        <div
          className="team-budget-bar__fill"
          style={{ width: `${percent}%` }}
          data-threshold-bucket={bucket}
        />
      </div>
    </div>
  )
}
