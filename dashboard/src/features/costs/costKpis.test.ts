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
  { team_id: 'team-hot', agent_count: 2, root_agent_count: 1, daily_spend_usd: 150, daily_limit_usd: 200, burn_pct: 75 },
]

describe('deriveCostKpis — daily / monthly / tracked figures', () => {
  it('derives daily and monthly spend, limit and burn %', () => {
    const kpis = deriveCostKpis(COSTS, TEAM_ROWS, 'daily')

    expect(kpis.daily).toEqual({ spend: 150, limit: 200, pct: 75 })
    expect(kpis.monthly).toEqual({ spend: 3200, limit: 5000, pct: 64 })
  })

  it('counts agents and teams tracked from the summary rows', () => {
    const kpis = deriveCostKpis(COSTS, TEAM_ROWS, 'daily')

    expect(kpis.agentsTracked).toBe(2)
    expect(kpis.teamsTracked).toBe(1)
  })

  it('daily/monthly figures are period-independent (identical under both toggles)', () => {
    const daily = deriveCostKpis(COSTS, TEAM_ROWS, 'daily')
    const monthly = deriveCostKpis(COSTS, TEAM_ROWS, 'monthly')

    expect(daily.daily).toEqual(monthly.daily)
    expect(daily.monthly).toEqual(monthly.monthly)
  })

  it('leaves limit/pct null when a period has no configured limit', () => {
    const noLimit: CostSummary = { date: '2026-05-13', daily_spend_usd: '42.00' }
    const kpis = deriveCostKpis(noLimit, [], 'daily')

    expect(kpis.daily).toEqual({ spend: 42, limit: null, pct: null })
    expect(kpis.monthly).toEqual({ spend: null, limit: null, pct: null })
  })

  it('degrades to zeros / nulls before any cost data arrives', () => {
    const kpis = deriveCostKpis(undefined, [], 'daily')

    expect(kpis.agentsTracked).toBe(0)
    expect(kpis.teamsTracked).toBe(0)
    expect(kpis.daily).toEqual({ spend: null, limit: null, pct: null })
  })
})
