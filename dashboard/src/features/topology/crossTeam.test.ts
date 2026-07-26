import { describe, expect, it } from 'vitest'
import { crossTeamDegreeByNode, crossTeamEdges, isCrossTeamEdge, teamById } from './crossTeam'
import type { TopologyEdge, TopologyNode } from './types'

function node(id: string, team: string): TopologyNode {
  return { id, name: id, status: 'active', team, owner: 'o', policyCount: 0, budgetSpend: 0, budgetLimit: null }
}

function edge(source: string, target: string, over: Partial<TopologyEdge> = {}): TopologyEdge {
  return { source, target, kind: 'delegation', ...over }
}

const NODES: readonly TopologyNode[] = [
  node('s1', 'support'),
  node('s2', 'support'),
  node('a1', 'analytics'),
  node('a2', 'analytics'),
]
const TEAMS = teamById(NODES)

describe('isCrossTeamEdge', () => {
  it('trusts the server flag over the endpoint teams', () => {
    // The server owns this classification (AAASM-5099); if it says an edge
    // between two same-team nodes crosses a boundary, the dashboard must not
    // silently overrule it — disagreeing with `/topology/edges` is the drift
    // this predicate exists to prevent.
    expect(isCrossTeamEdge(edge('s1', 's2', { crossTeam: true }), TEAMS)).toBe(true)
    expect(isCrossTeamEdge(edge('s1', 'a1', { crossTeam: false }), TEAMS)).toBe(false)
  })

  it('falls back to comparing endpoint teams when the flag is absent', () => {
    expect(isCrossTeamEdge(edge('s1', 'a1'), TEAMS)).toBe(true)
    expect(isCrossTeamEdge(edge('s1', 's2'), TEAMS)).toBe(false)
  })

  it('does not claim a crossing it cannot demonstrate', () => {
    // An unresolvable endpoint means the edge is unclassifiable. Counting it as
    // cross-team would inflate the sidebar with edges that may be intra-team.
    expect(isCrossTeamEdge(edge('s1', 'ghost'), TEAMS)).toBe(false)
    expect(isCrossTeamEdge(edge('ghost', 'other-ghost'), TEAMS)).toBe(false)
  })
})

describe('crossTeamEdges', () => {
  it('keeps only boundary-crossing edges, in input order', () => {
    const edges = [edge('s1', 's2'), edge('s1', 'a1'), edge('s2', 'a2'), edge('a1', 'a2')]
    expect(crossTeamEdges(edges, TEAMS)).toEqual([edge('s1', 'a1'), edge('s2', 'a2')])
  })

  it('is empty for a single-team graph', () => {
    expect(crossTeamEdges([edge('s1', 's2')], TEAMS)).toEqual([])
  })
})

describe('crossTeamDegreeByNode', () => {
  it('counts both endpoints of each crossing', () => {
    const degree = crossTeamDegreeByNode([edge('s1', 'a1'), edge('s2', 'a1')], TEAMS)
    expect(degree.get('s1')).toBe(1)
    expect(degree.get('s2')).toBe(1)
    expect(degree.get('a1')).toBe(2)
  })

  it('omits nodes with no cross-team edge rather than recording a zero', () => {
    const degree = crossTeamDegreeByNode([edge('s1', 'a1'), edge('s2', 's1')], TEAMS)
    expect(degree.has('s2')).toBe(false)
  })

  it('ignores a self-edge, which cannot cross a boundary', () => {
    // Counting one would add 2 to a single node's degree for an edge that does
    // not leave its team at all.
    const degree = crossTeamDegreeByNode([edge('s1', 's1', { crossTeam: true })], TEAMS)
    expect(degree.get('s1')).toBeUndefined()
  })

  /**
   * The invariant the sidebar counter and the card badges both rest on.
   *
   * With a team filter active, every cross-team edge touching that team has
   * exactly one endpoint on screen — so the badges over the team's own nodes sum
   * to precisely the number of that team's crossings. That equality is what lets
   * the badge account for edges the canvas dropped without double-counting or
   * missing any.
   */
  it('sums per-team badges to that team’s crossing count', () => {
    const edges = [edge('s1', 'a1'), edge('s2', 'a1'), edge('s2', 'a2'), edge('a1', 'a2'), edge('s1', 's2')]
    const degree = crossTeamDegreeByNode(edges, TEAMS)

    const supportIds = NODES.filter((n) => n.team === 'support').map((n) => n.id)
    const badgeSum = supportIds.reduce((total, id) => total + (degree.get(id) ?? 0), 0)
    const supportCrossings = crossTeamEdges(edges, TEAMS).filter(
      (e) => TEAMS.get(e.source) === 'support' || TEAMS.get(e.target) === 'support',
    ).length

    expect(badgeSum).toBe(supportCrossings)
    expect(badgeSum).toBe(3)
  })
})

describe('teamById', () => {
  it('maps every node id to its team', () => {
    expect(teamById(NODES).get('a2')).toBe('analytics')
    expect(teamById([]).size).toBe(0)
  })
})
