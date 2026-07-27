import { describe, expect, it } from 'vitest'
import { absent, isKnown, known } from '../../lib/truthfulness'
import { isOrphanAgent, reconcileAgentCensus, selectOrphanAgents } from './orphans'
import type { AgentNode, TopologyOverview } from './api'

function agent(over: Partial<AgentNode> & Pick<AgentNode, 'id'>): AgentNode {
  return { name: over.id, status: 'active', depth: 0, flagged: false, mode: 'enforce', trust: null, ...over }
}

function overview(teams: TopologyOverview['teams'], total: number): TopologyOverview {
  return {
    teams,
    team_count: teams.length,
    root_agent_count: 0,
    standalone_root_agents: [],
    total_agent_count: total,
  }
}

const TEAM = (team_id: string, agent_count: number) => ({ team_id, agent_count, root_agent_count: 1 })

describe('isOrphanAgent', () => {
  it('treats a spawned agent with no team as an orphan', () => {
    expect(isOrphanAgent(agent({ id: 'spawned', depth: 4, team_id: null }))).toBe(true)
  })

  it('treats an omitted team field as no team', () => {
    expect(isOrphanAgent(agent({ id: 'root' }))).toBe(true)
  })

  it('treats a blank team id as no team', () => {
    expect(isOrphanAgent(agent({ id: 'blank', team_id: '' }))).toBe(true)
  })

  it.each([
    ['spaces', '   '],
    ['a tab', '\t'],
    ['a newline', '\n'],
  ])('treats a team id of only %s as no team', (_label, teamId) => {
    // The registry accepts it — `validate_tenant_id` (AAASM-4190) rejects
    // control characters only — and the gateway folds it to no team in
    // `team_of` (AAASM-5182). Calling such an agent claimed here would have the
    // dashboard and the gateway give opposite answers about one agent, and on
    // Topology it reinstated the phantom team this vocabulary exists to end
    // (AAASM-5184).
    expect(isOrphanAgent(agent({ id: 'ws', team_id: teamId }))).toBe(true)
  })

  it('does not trim a real team id into a different team', () => {
    // Only *emptiness* is decided by the trim. A padded id is still that team,
    // so the agent is claimed — the gateway keys on the registered id too.
    expect(isOrphanAgent(agent({ id: 'padded', team_id: ' platform ' }))).toBe(false)
  })

  it('never calls a claimed agent an orphan, at any depth', () => {
    expect(isOrphanAgent(agent({ id: 'r', team_id: 'platform' }))).toBe(false)
    expect(isOrphanAgent(agent({ id: 'c', depth: 7, team_id: 'platform' }))).toBe(false)
  })
})

describe('selectOrphanAgents', () => {
  it('keeps every team-less agent regardless of depth, in input order', () => {
    const nodes = [
      agent({ id: 'a', team_id: 'platform' }),
      agent({ id: 'b', depth: 1 }),
      agent({ id: 'c', depth: 2, team_id: 'platform' }),
      agent({ id: 'd' }),
      agent({ id: 'e', team_id: '   ' }),
    ]
    expect(selectOrphanAgents(nodes).map(n => n.id)).toEqual(['b', 'd', 'e'])
  })

  it('returns an empty list when every agent is claimed — a real answer, not an absence', () => {
    expect(selectOrphanAgents([agent({ id: 'a', team_id: 'platform' })])).toEqual([])
  })
})

describe('reconcileAgentCensus', () => {
  it('reconciles when the groupings cover the registry tally', () => {
    const census = reconcileAgentCensus(
      known(overview([TEAM('platform', 3), TEAM('data', 2)], 6)),
      known([agent({ id: 'o1' })]),
    )
    expect(census).toEqual(known({ grouped: 6, total: 6, unaccountedFor: 0 }))
  })

  it('reports the size of the disagreement', () => {
    const census = reconcileAgentCensus(known(overview([TEAM('platform', 3)], 5)), known([agent({ id: 'o1' })]))
    expect(isKnown(census) && census.value.unaccountedFor).toBe(1)
  })

  it('reports a negative difference rather than clamping it away', () => {
    const census = reconcileAgentCensus(known(overview([TEAM('platform', 3)], 2)), known([agent({ id: 'o1' })]))
    expect(isKnown(census) && census.value.unaccountedFor).toBe(-2)
  })

  it('has no verdict when the registry side is withheld, and keeps its reason', () => {
    expect(reconcileAgentCensus(absent('unknown', 'Both sources are being refreshed'), known([]))).toEqual(
      absent('unknown', 'Both sources are being refreshed'),
    )
  })

  it('has no verdict when the unclaimed set could not be counted', () => {
    expect(reconcileAgentCensus(known(overview([TEAM('platform', 3)], 3)), absent('unavailable'))).toEqual(
      absent('unknown', 'Unclaimed agents could not be counted'),
    )
  })

  it('counts a zero-agent team as a real zero, not a missing value', () => {
    const census = reconcileAgentCensus(known(overview([TEAM('empty', 0)], 0)), known([]))
    expect(census).toEqual(known({ grouped: 0, total: 0, unaccountedFor: 0 }))
  })
})
