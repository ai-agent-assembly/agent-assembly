import { bucketForBudget } from '../../components/topology/budgetThreshold'
import type { CostSummary, TeamListRow } from '../teams/api'

/**
 * The two budget periods the Cost & Budget page can scope its per-team bars to.
 * The OSS `/api/v1/costs` summary only carries an org-level limit, so utilisation
 * is "team spend vs the org limit for the period" — i.e. each team's share of the
 * org budget — not a per-team configured limit (which the OSS API does not expose).
 */
export type BudgetPeriod = 'daily' | 'monthly'

/**
 * Org spend against its configured limit for one budget period, plus the
 * derived burn percentage. Backs a Daily / Monthly KPI card and its mini
 * budget bar. `limit`/`pct` are `null` when no limit is configured (the OSS
 * API omits the field), so the card degrades to "no limit" rather than NaN.
 */
export interface PeriodSpend {
  readonly spend: number | null
  readonly limit: number | null
  readonly pct: number | null
}

export interface CostKpis {
  /** Total org spend for the active period, in USD. `null` when unavailable. */
  readonly totalSpend: number | null
  /** Org limit for the active period, in USD. `null` when no limit is configured. */
  readonly limit: number | null
  /** `totalSpend / limit * 100`, or `null` when either side is missing. */
  readonly utilisationPct: number | null
  /** Highest-spend agent for the active period, or `null` when there is no data. */
  readonly topConsumer: { readonly agentId: string; readonly spend: number } | null
  /**
   * Number of teams whose burn against the org limit is in the `danger` bucket
   * (≥ 95%) — the teams a budget enforcer would be blocking right now.
   */
  readonly blockedByBudget: number
  /** Daily spend vs the configured daily limit (period-independent — always daily). */
  readonly daily: PeriodSpend
  /** Monthly spend vs the configured monthly limit (period-independent — always monthly). */
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

function topConsumer(
  costs: CostSummary | undefined,
  period: BudgetPeriod,
): { agentId: string; spend: number } | null {
  let best: { agentId: string; spend: number } | null = null
  for (const entry of costs?.per_agent ?? []) {
    const spend = parseUsd(period === 'daily' ? entry.daily_spend_usd : entry.monthly_spend_usd)
    if (spend == null) continue
    if (best == null || spend > best.spend) best = { agentId: entry.agent_id, spend }
  }
  return best
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
 */
export function deriveCostKpis(
  costs: CostSummary | undefined,
  teamRows: readonly TeamListRow[],
  period: BudgetPeriod,
): CostKpis {
  const totalSpend = parseUsd(
    period === 'daily' ? costs?.daily_spend_usd : costs?.monthly_spend_usd,
  )
  const limit = parseUsd(period === 'daily' ? costs?.daily_limit_usd : costs?.monthly_limit_usd)
  const utilisationPct =
    totalSpend != null && limit != null && limit > 0 ? (totalSpend / limit) * 100 : null

  const blockedByBudget = teamRows.reduce((count, row) => {
    if (row.daily_spend_usd == null || row.daily_limit_usd == null) return count
    return bucketForBudget(row.daily_spend_usd, row.daily_limit_usd) === 'danger' ? count + 1 : count
  }, 0)

  return {
    totalSpend,
    limit,
    utilisationPct,
    topConsumer: topConsumer(costs, period),
    blockedByBudget,
    daily: periodSpend(costs?.daily_spend_usd, costs?.daily_limit_usd),
    monthly: periodSpend(costs?.monthly_spend_usd, costs?.monthly_limit_usd),
    agentsTracked: costs?.per_agent?.length ?? 0,
    teamsTracked: costs?.per_team?.length ?? 0,
  }
}
