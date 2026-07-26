import { AbsenceMarker } from '../truthfulness'
import { bucketForBudget } from './budgetThreshold'
import './TeamBudgetBar.css'

/** What the operator is told when no ceiling has been configured. */
const NO_LIMIT_DETAIL = 'No daily budget limit is configured'

export interface TeamBudgetBarProps {
  readonly team: string
  readonly spent: number
  /**
   * The budget ceiling in USD, or `null` when none is configured (AAASM-5135).
   *
   * `null` is not `0`. A configured `$0` ceiling is a real fact that any spend
   * at all exceeds; an absent one means nothing has been set, so there is no
   * burn ratio to report and no threshold band that applies. The bar renders
   * the two differently and never invents a percentage for the second.
   */
  readonly limit: number | null
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
 *
 * With no configured limit the bar becomes an *indeterminate* progressbar: it
 * carries no `aria-valuenow`, which is ARIA's own way of saying the current
 * value is unknown. Emitting `aria-valuenow={0}` there would announce a wholly
 * unburnt budget on evidence that does not exist — the same claim as the
 * visible `$0 / $0 · 0%` this replaces (AAASM-5135). No fill is drawn either:
 * a zero-width fill is still a rendered measurement of zero.
 */
export function TeamBudgetBar({ team, spent, limit }: TeamBudgetBarProps) {
  const hasLimit = limit !== null
  const bucket = hasLimit ? bucketForBudget(spent, limit) : undefined
  const percent = hasLimit && limit > 0 ? Math.round(Math.min(1, spent / limit) * 100) : 0

  return (
    <div
      className="team-budget-bar"
      data-testid="team-budget-bar"
      data-team={team}
      data-threshold-bucket={bucket}
      data-truth-state={hasLimit ? undefined : 'unconfigured'}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={hasLimit ? percent : undefined}
      aria-label={
        hasLimit
          ? `${team} budget burn ${percent}%`
          : `${team} budget burn unknown — no daily budget limit is configured`
      }
    >
      <div className="team-budget-bar__head">
        <span className="team-budget-bar__team">{team}</span>
        <span className="team-budget-bar__amount" data-testid="team-budget-bar-amount">
          {hasLimit ? (
            `$${spent.toFixed(0)} / $${limit.toFixed(0)} · ${percent}%`
          ) : (
            <>
              ${spent.toFixed(0)} /{' '}
              <AbsenceMarker
                state="unconfigured"
                detail={NO_LIMIT_DETAIL}
                testId="team-budget-bar-no-limit"
              />
            </>
          )}
        </span>
      </div>
      <div
        className="team-budget-bar__track"
        data-truth-state={hasLimit ? undefined : 'unconfigured'}
      >
        {hasLimit && (
          <div
            className="team-budget-bar__fill"
            style={{ width: `${percent}%` }}
            data-threshold-bucket={bucket}
          />
        )}
      </div>
    </div>
  )
}
