import { describe, expect, it } from 'vitest'
import { buildPerAgentRows } from './perAgentRows'
import type { CostSummary } from '../teams/api'

const COSTS: CostSummary = {
  date: '2026-05-13',
  daily_spend_usd: '190.00',
  per_agent: [
    { agent_id: 'agent-mid', daily_spend_usd: '80.00', date: '2026-05-13', monthly_spend_usd: '1600.00' },
    { agent_id: 'agent-top', daily_spend_usd: '160.00', date: '2026-05-13', monthly_spend_usd: '3200.00' },
    { agent_id: 'agent-idle', daily_spend_usd: '0.00', date: '2026-05-13', monthly_spend_usd: null },
  ],
}

const TEAMS = new Map<string, string>([
  ['agent-top', 'team-hot'],
  ['agent-mid', 'team-cool'],
])

describe('buildPerAgentRows', () => {
  it('sorts by daily spend descending', () => {
    const rows = buildPerAgentRows(COSTS, TEAMS)
    expect(rows.map(r => r.agentId)).toEqual(['agent-top', 'agent-mid', 'agent-idle'])
  })

  it('resolves team from the topology map, null when unknown', () => {
    const rows = buildPerAgentRows(COSTS, TEAMS)
    expect(rows.find(r => r.agentId === 'agent-top')?.team).toBe('team-hot')
    expect(rows.find(r => r.agentId === 'agent-idle')?.team).toBeNull()
  })

  it('computes share as a percentage of the top daily spender', () => {
    const rows = buildPerAgentRows(COSTS, TEAMS)
    expect(rows.find(r => r.agentId === 'agent-top')?.sharePct).toBe(100)
    expect(rows.find(r => r.agentId === 'agent-mid')?.sharePct).toBe(50)
    expect(rows.find(r => r.agentId === 'agent-idle')?.sharePct).toBe(0)
  })

  it('carries monthly spend through, null when untracked', () => {
    const rows = buildPerAgentRows(COSTS, TEAMS)
    expect(rows.find(r => r.agentId === 'agent-top')?.monthly).toBe(3200)
    expect(rows.find(r => r.agentId === 'agent-idle')?.monthly).toBeNull()
  })

  it('returns an empty array when there is no cost data', () => {
    expect(buildPerAgentRows(undefined, TEAMS)).toEqual([])
  })
})
