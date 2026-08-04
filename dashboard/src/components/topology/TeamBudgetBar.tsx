import { AbsenceMarker } from '../truthfulness'
import { bucketForConfiguredBudget, burnPercentForConfiguredBudget } from './budgetThreshold'
import './TeamBudgetBar.css'

/** What the operator is told when no ceiling has been configured. */
const NO_LIMIT_DETAIL = 'No daily budget limit is configured'
/** What the operator is told when the spend figure never arrived. */
const NO_SPEND_DETAIL = 'No spend figure is available for this team'

export interface TeamBudgetBarProps {
  readonly team: string
  /**
   * Spend so far in USD, or `null` when no figure is available (AAASM-5135).
   *
   * Nullable because the Costs page's `TeamListRow.daily_spend_usd` is: it is
   * `parseUsd(cost?.daily_spend_usd)`, which yields `null` for a team absent
   * from the cost breakdown *and* for every team while the costs query is
   * unresolved or failed. Rendering that as `$0` would report a team that spent
   * nothing when the truth is that nobody asked or the request failed.
   */
  readonly spent: number | null
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
 * Team-level budget bar shown above each topology team cluster (AAASM-1339) and
 * on the Costs page's per-team list.
 *
 * Threshold buckets:
 *   - `ok`     ratio  < 0.80   → `--ok`
 *   - `warn`   0.80 ≤ ratio < 0.95 → `--warn`
 *   - `danger` ratio ≥ 0.95   → `--danger`
 *
 * Same threshold contract as the AAASM-1337 node-detail-panel progress bar,
 * except at a *configured* `$0` ceiling: `bucketForConfiguredBudget` reports
 * that fully burnt rather than `ok`, because the gateway denies on
 * `spent >= limit`, so `$0` permits nothing. The plain `bucketForBudget` still
 * backs topology, where a non-positive divisor means a missing ceiling instead.
 * Sharing the rule with the spend cell beside this bar is what stops one team
 * row reporting `danger` in one cell and `ok` in the next (AAASM-5185).
 *
 * A percentage needs *both* numbers. Missing either makes the bar an
 * *indeterminate* progressbar: it carries no `aria-valuenow`, which is ARIA's
 * own way of saying the current value is unknown. Emitting `aria-valuenow={0}`
 * would announce a wholly unburnt budget on evidence that does not exist — the
 * same claim as the visible `$0 / $0 · 0%` this replaces (AAASM-5135). No fill
 * is drawn either: a zero-width fill is still a rendered measurement of zero.
 *
 * The two absences are reported with different states because they are
 * different facts: an absent ceiling is `unconfigured` (nothing was set up),
 * while an absent spend is `unknown` (we asked and did not get an answer).
 */
export function TeamBudgetBar({ team, spent, limit }: TeamBudgetBarProps) {
  const hasSpend = spent !== null
  const hasLimit = limit !== null
  const measurable = hasSpend && hasLimit
  const bucket = measurable ? bucketForConfiguredBudget(spent, limit) : undefined
  const percent = measurable ? Math.round(burnPercentForConfiguredBudget(spent, limit)) : 0

  let truthState: string | undefined
  if (!hasSpend) truthState = 'unknown'
  else if (!hasLimit) truthState = 'unconfigured'

  const unmeasurableDetail = hasSpend ? NO_LIMIT_DETAIL.toLowerCase() : NO_SPEND_DETAIL.toLowerCase()

  return (
    <div
      className="team-budget-bar"
      data-testid="team-budget-bar"
      data-team={team}
      data-threshold-bucket={bucket}
      data-truth-state={truthState}
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={measurable ? percent : undefined}
      aria-label={
        measurable
          ? `${team} budget burn ${percent}%`
          : `${team} budget burn unknown — ${unmeasurableDetail}`
      }
    >
      <div className="team-budget-bar__head">
        <span className="team-budget-bar__team">{team}</span>
        <span className="team-budget-bar__amount" data-testid="team-budget-bar-amount">
          {measurable ? (
            `$${spent.toFixed(0)} / $${limit.toFixed(0)} · ${percent}%`
          ) : (
            <>
              {hasSpend ? (
                `$${spent.toFixed(0)}`
              ) : (
                <AbsenceMarker state="unknown" detail={NO_SPEND_DETAIL} testId="team-budget-bar-no-spend" />
              )}
              {' / '}
              {hasLimit ? (
                `$${limit.toFixed(0)}`
              ) : (
                <AbsenceMarker
                  state="unconfigured"
                  detail={NO_LIMIT_DETAIL}
                  testId="team-budget-bar-no-limit"
                />
              )}
            </>
          )}
        </span>
      </div>
      <div className="team-budget-bar__track" data-truth-state={truthState}>
        {measurable && (
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
