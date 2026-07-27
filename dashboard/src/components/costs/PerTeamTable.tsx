import { TeamBudgetBar } from '../topology/TeamBudgetBar'
import { AbsenceMarker } from '../truthfulness'
import { bucketForConfiguredBudget } from '../topology/budgetThreshold'
import type { TeamListRow } from '../../features/teams/api'
import './PerTeamTable.css'

interface PerTeamTableProps {
  readonly rows: readonly TeamListRow[]
}

/** What the operator is told when a figure never arrived. */
const NO_DAILY_DETAIL = 'No daily spend figure is available for this team'
const NO_MONTHLY_TRACKED_DETAIL = 'Monthly spend tracking is not enabled for this team'
const NO_MONTHLY_ROW_DETAIL = 'This team has no row in the cost breakdown'

/** Burn bucket for the daily figure's ink, or `undefined` when unmeasurable. */
function dailyBucket(row: TeamListRow): string | undefined {
  if (row.daily_spend_usd == null || row.daily_limit_usd == null) return undefined
  return bucketForConfiguredBudget(row.daily_spend_usd, row.daily_limit_usd)
}

/**
 * Per-team cost table for the Costs page Per-team tab, restoring the table
 * shape of `design/v1/hi-fi/costs.jsx:428-478` and `design/v2/hi-fi/costs.jsx`
 * (v2 authoritative per ADR-0025): Team | Agents | Daily spend | vs daily limit
 * | Monthly spend (AAASM-5160).
 *
 * It replaces a flat list of `TeamBudgetBar`, which showed team and burn only —
 * so team size was invisible on the only per-team cost surface, and the product
 * carried no per-team monthly figure anywhere despite
 * `TeamCostEntry.monthly_spend_usd` and `TeamSummary.agent_count` both already
 * being on the wire. The bar itself is kept verbatim as the "vs daily limit"
 * cell rather than reimplemented, so its absence handling (no `aria-valuenow`,
 * no threshold bucket, no `$0 / $0 · 0%` for an unmeasured budget — AAASM-5135)
 * continues to hold unchanged.
 *
 * The mock's neighbouring **Monthly limit** column is deliberately absent. The
 * mock sources it from `window.TEAM_DETAILS`, not the API; `TeamCostEntry`
 * carries no ceiling of any window, and a team-tier monthly limit is sign-off-
 * gated on ADR-0020 / AAASM-5087. A fabricated ceiling is worse than a missing
 * column, so the column waits for the field.
 */
export function PerTeamTable({ rows }: PerTeamTableProps) {
  return (
    <div className="costs-team-table__scroll">
      <table className="costs-team-table" data-testid="costs-team-table">
        <thead>
          <tr>
            <th>Team</th>
            <th>Agents</th>
            <th>Daily spend</th>
            <th className="costs-team-table__bar-col">vs daily limit</th>
            <th>Monthly spend</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(row => (
            <tr key={row.team_id} data-testid="costs-team-row" data-team={row.team_id}>
              <td className="costs-team-table__id">{row.team_id}</td>
              <td>
                {/* Non-nullable on the wire (`TeamSummary.agent_count`), so a
                    real `0` here means a team with no agents, not an unknown. */}
                <span className="costs-team-table__agents" data-testid="costs-team-agents">
                  {row.agent_count}
                </span>
              </td>
              <td>
                <span className="costs-team-table__daily" data-threshold-bucket={dailyBucket(row)}>
                  {row.daily_spend_usd == null ? (
                    <AbsenceMarker
                      state="unknown"
                      detail={NO_DAILY_DETAIL}
                      testId="costs-team-no-daily"
                    />
                  ) : (
                    `$${row.daily_spend_usd.toFixed(2)}`
                  )}
                </span>
              </td>
              <td className="costs-team-table__bar-col">
                <TeamBudgetBar
                  team={row.team_id}
                  spent={row.daily_spend_usd}
                  limit={row.daily_limit_usd}
                />
              </td>
              <td className="costs-team-table__monthly">
                {row.monthly_spend_usd == null ? (
                  // Two different absences, told apart by whether the team
                  // appeared in the breakdown at all: a row with a daily figure
                  // and no monthly one means monthly tracking is off, while a
                  // row with neither means nothing was measured for this team.
                  // `$0` would be a claim of a month without spend.
                  <AbsenceMarker
                    state={row.daily_spend_usd == null ? 'unknown' : 'unconfigured'}
                    detail={
                      row.daily_spend_usd == null
                        ? NO_MONTHLY_ROW_DETAIL
                        : NO_MONTHLY_TRACKED_DETAIL
                    }
                    testId="costs-team-no-monthly"
                  />
                ) : (
                  `$${row.monthly_spend_usd.toFixed(2)}`
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
