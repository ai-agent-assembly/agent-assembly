import type { CostSummary } from '../teams/api'

/** One row of the Costs per-agent table (design/v1/hi-fi/costs.jsx Per-agent tab). */
export interface PerAgentRow {
  readonly agentId: string
  /** Owning team, resolved from the topology graph. `null` when unknown/standalone. */
  readonly team: string | null
  /** Daily spend in USD, or `null` when unparseable. */
  readonly daily: number | null
  /** Monthly spend in USD, or `null` when monthly tracking is off for this agent. */
  readonly monthly: number | null
  /**
   * Daily spend as a percentage of the highest daily spender in the set (0–100).
   * Drives the relative in-row bar; this is a share-of-top figure, NOT a budget
   * burn — the per-agent summary carries no per-agent limit.
   */
  readonly sharePct: number
}

function parseUsd(value: string | null | undefined): number | null {
  if (value == null) return null
  const n = Number.parseFloat(value)
  return Number.isFinite(n) ? n : null
}

/**
 * Build the per-agent table rows from the cost summary, joining each agent to
 * its team via the topology-derived `agentTeams` map and computing each row's
 * share of the top daily spender. Rows are sorted by daily spend descending
 * (nulls last) so the biggest consumer leads and the relative bar reads
 * left-heavy. The 7-day per-agent trend sparkline the mock shows is deliberately
 * omitted — there is no per-agent history endpoint to source it (AAASM-5076).
 */
export function buildPerAgentRows(
  costs: CostSummary | undefined,
  agentTeams: ReadonlyMap<string, string>,
): PerAgentRow[] {
  const entries = costs?.per_agent ?? []
  const parsed = entries.map(entry => ({
    agentId: entry.agent_id,
    team: agentTeams.get(entry.agent_id) ?? null,
    daily: parseUsd(entry.daily_spend_usd),
    monthly: parseUsd(entry.monthly_spend_usd),
  }))

  const maxDaily = parsed.reduce((max, row) => (row.daily != null && row.daily > max ? row.daily : max), 0)

  return parsed
    .map(row => ({
      ...row,
      sharePct: row.daily != null && maxDaily > 0 ? (row.daily / maxDaily) * 100 : 0,
    }))
    .sort((a, b) => (b.daily ?? -1) - (a.daily ?? -1))
}
