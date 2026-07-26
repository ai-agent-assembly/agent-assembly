import { bucketForBudget } from '../../components/topology/budgetThreshold'
import type { CostSummary, TeamListRow } from '../teams/api'

/**
 * The two budget periods `/api/v1/costs` reports.
 *
 * Both are shown at once — as their own KPI cards — rather than selected
 * between. The page used to carry a Daily/Monthly segmented control, but the
 * only figure it could actually move was a utilisation percentage already
 * printed on the card beside it; everything else on the page (the per-team
 * bars, the blocked-by-budget count, the burn callouts) is daily and stayed
 * daily while the labels flipped (AAASM-5126). See `CostsPage`.
 */
export type BudgetPeriod = 'daily' | 'monthly'

/**
 * Org spend against its configured limit for one budget period, plus the
 * derived burn percentage. Backs a Daily / Monthly KPI card and its mini
 * budget bar.
 *
 * Every field is nullable and none of them defaults to `0`. `limit` is absent
 * when none is configured; `spend` is absent for the monthly window until a
 * monthly limit exists at all, because the gateway only starts accumulating
 * `monthly_spent_usd` once one is configured; `pct` needs both.
 */
export interface PeriodSpend {
  readonly spend: number | null
  readonly limit: number | null
  readonly pct: number | null
}

export interface CostKpis {
  /**
   * Number of teams whose burn against the org daily limit is in the `danger`
   * bucket (≥ 95%) — the teams a budget enforcer would be blocking right now.
   *
   * Daily, and only daily: there is no per-team monthly ceiling anywhere on
   * the wire (`TeamCostEntry` carries spend and no limit), and adding one is
   * sign-off-gated on ADR-0020 / AAASM-5087. Any monthly variant of this count
   * would have no denominator.
   */
  readonly blockedByBudget: number
  /** Org spend vs the configured daily limit. */
  readonly daily: PeriodSpend
  /** Org spend vs the configured monthly limit. */
  readonly monthly: PeriodSpend
  /** Number of agents with a per-agent cost row today. */
  readonly agentsTracked: number
  /** Number of teams with a per-team cost row today (the "across N teams" figure). */
  readonly teamsTracked: number
}

function parseUsd(value: string | null | undefined): number | null {
  if (value == null) return null
  const n = Number.parseFloat(value)
  return Number.isFinite(n) ? n : null
}

/** Spend/limit/burn-% for one period, from its raw string-encoded USD figures. */
function periodSpend(
  spendRaw: string | null | undefined,
  limitRaw: string | null | undefined,
): PeriodSpend {
  const spend = parseUsd(spendRaw)
  const limit = parseUsd(limitRaw)
  const pct = spend != null && limit != null && limit > 0 ? (spend / limit) * 100 : null
  return { spend, limit, pct }
}

/**
 * Derive the KPI-strip figures for the Cost & Budget page from the cost summary
 * and the already-joined per-team rows. Pure so it can be unit-tested without a
 * query client; both inputs may be `undefined`/empty before data arrives.
 *
 * Deliberately takes no period argument. Every figure it returns is labelled
 * with the window it came from, so no caller can present one window's number
 * under another's heading.
 */
export function deriveCostKpis(
  costs: CostSummary | undefined,
  teamRows: readonly TeamListRow[],
): CostKpis {
  const blockedByBudget = teamRows.reduce((count, row) => {
    if (row.daily_spend_usd == null || row.daily_limit_usd == null) return count
    return bucketForBudget(row.daily_spend_usd, row.daily_limit_usd) === 'danger' ? count + 1 : count
  }, 0)

  return {
    blockedByBudget,
    daily: periodSpend(costs?.daily_spend_usd, costs?.daily_limit_usd),
    monthly: periodSpend(costs?.monthly_spend_usd, costs?.monthly_limit_usd),
    agentsTracked: costs?.per_agent?.length ?? 0,
    teamsTracked: costs?.per_team?.length ?? 0,
  }
}
