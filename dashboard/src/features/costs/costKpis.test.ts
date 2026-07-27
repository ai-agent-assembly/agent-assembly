import { describe, expect, it } from 'vitest'
import { deriveCostKpis } from './costKpis'
import type { CostSummary, TeamListRow } from '../teams/api'

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '150.00',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3200.00',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'agent-spendy', daily_spend_usd: '120.00', date: '2026-05-13', monthly_spend_usd: '2400.00' },
    { agent_id: 'agent-thrifty', daily_spend_usd: '30.00', date: '2026-05-13', monthly_spend_usd: '800.00' },
  ],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '150.00', date: '2026-05-13', monthly_spend_usd: '3200.00' },
  ],
}

const TEAM_ROWS: readonly TeamListRow[] = [
  { team_id: 'team-hot', agent_count: 2, root_agent_count: 1, daily_spend_usd: 150, daily_limit_usd: 200, monthly_spend_usd: 3200, burn_pct: 75 },
]

describe('deriveCostKpis — daily / monthly / tracked figures', () => {
  it('derives daily and monthly spend, limit and burn %', () => {
    const kpis = deriveCostKpis(COSTS, TEAM_ROWS)

    expect(kpis.daily).toEqual({ spend: 150, limit: 200, pct: 75 })
    expect(kpis.monthly).toEqual({ spend: 3200, limit: 5000, pct: 64 })
  })

  it('counts agents and teams tracked from the summary rows', () => {
    const kpis = deriveCostKpis(COSTS, TEAM_ROWS)

    expect(kpis.agentsTracked).toBe(2)
    expect(kpis.teamsTracked).toBe(1)
  })

  it('leaves limit/pct null when a period has no configured limit', () => {
    const noLimit: CostSummary = { date: '2026-05-13', daily_spend_usd: '42.00' }
    const kpis = deriveCostKpis(noLimit, [])

    expect(kpis.daily).toEqual({ spend: 42, limit: null, pct: null })
    expect(kpis.monthly).toEqual({ spend: null, limit: null, pct: null })
  })

  it('degrades to zeros / nulls before any cost data arrives', () => {
    const kpis = deriveCostKpis(undefined, [])

    expect(kpis.agentsTracked).toBe(0)
    expect(kpis.teamsTracked).toBe(0)
    expect(kpis.daily).toEqual({ spend: null, limit: null, pct: null })
  })

  describe('AAASM-5126 — no figure can be presented under another window’s heading', () => {
    it('exposes each window only under its own key, with no period-selected alias', () => {
      // The removed `period` argument used to re-key one of these two as
      // `totalSpend` / `limit` / `utilisationPct`, which is how "Monthly" came
      // to head a strip whose other figures were still daily. The shape now
      // makes that unexpressible: a caller must name the window it wants.
      const kpis = deriveCostKpis(COSTS, TEAM_ROWS)

      expect(Object.keys(kpis).sort()).toEqual([
        'agentsTracked',
        'blockedByBudget',
        'daily',
        'monthly',
        'teamsTracked',
      ])
      expect(kpis.daily).not.toEqual(kpis.monthly)
    })

    it('counts blocked teams against the daily ceiling only — the sole one on the wire', () => {
      // `TeamCostEntry` carries monthly spend but no limit of any window, and a
      // team-tier monthly ceiling is sign-off-gated on ADR-0020 / AAASM-5087.
      // A monthly variant of this count would have no denominator, so the
      // figure is daily and is labelled daily rather than following a toggle.
      const rows: readonly TeamListRow[] = [
        // 195/200 = 97.5% — danger.
        { team_id: 'team-hot', agent_count: 2, root_agent_count: 1, daily_spend_usd: 195, daily_limit_usd: 200, monthly_spend_usd: null, burn_pct: 97.5 },
        // 20/200 = 10% — ok.
        { team_id: 'team-cool', agent_count: 1, root_agent_count: 1, daily_spend_usd: 20, daily_limit_usd: 200, monthly_spend_usd: null, burn_pct: 10 },
      ]

      expect(deriveCostKpis(COSTS, rows).blockedByBudget).toBe(1)
    })

    it('never counts a team whose ceiling is unknown as either blocked or safe', () => {
      // An unresolved `/costs` leaves every joined row null on both sides. The
      // count reports what it measured — one blocked team out of the one it
      // could measure — rather than absorbing the unmeasured rows as compliant.
      const rows: readonly TeamListRow[] = [
        { team_id: 'team-unknown', agent_count: 2, root_agent_count: 1, daily_spend_usd: null, daily_limit_usd: null, monthly_spend_usd: null, burn_pct: null },
        { team_id: 'team-nolimit', agent_count: 2, root_agent_count: 1, daily_spend_usd: 900, daily_limit_usd: null, monthly_spend_usd: null, burn_pct: null },
        { team_id: 'team-hot', agent_count: 2, root_agent_count: 1, daily_spend_usd: 195, daily_limit_usd: 200, monthly_spend_usd: null, burn_pct: 97.5 },
      ]

      expect(deriveCostKpis(COSTS, rows).blockedByBudget).toBe(1)
    })
  })
})
