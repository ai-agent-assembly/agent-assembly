import { describe, expect, it } from 'vitest'
import {
  crossTeamDegreeByNode,
  crossTeamEdges,
  hiddenCrossTeamCount,
  isCrossTeamEdge,
  isEdgeDrawn,
  teamById,
} from './crossTeam'
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

// ── The reconciliation the sidebar depends on (AAASM-5138) ───────────────────
//
// An earlier revision of this lane claimed `drawn + badged == counted` and
// tested it on a 2-team fixture in which every crossing touched the filtered
// team — a shape in which the claim cannot fail. It is false in general, and
// these are the cases that break it. The shipped counter therefore reports
// `counted − drawn`, which is what these lock down.
describe('hiddenCrossTeamCount', () => {
  const THREE_TEAM_NODES: readonly TopologyNode[] = [
    node('a1', 'alpha'),
    node('b1', 'beta'),
    node('c1', 'gamma'),
  ]
  const THREE_TEAMS = teamById(THREE_TEAM_NODES)
  // alpha–beta and beta–gamma. Filtering to alpha leaves beta–gamma counted but
  // touching no visible node at all, so no badge can ever represent it.
  const CHAIN = [edge('a1', 'b1'), edge('b1', 'c1')]

  it('counts a crossing between two off-screen teams as hidden', () => {
    const visible = new Set(['a1'])
    expect(crossTeamEdges(CHAIN, THREE_TEAMS)).toHaveLength(2)
    expect(hiddenCrossTeamCount(CHAIN, visible, THREE_TEAMS)).toBe(2)

    // The badges over the visible team account for only one of the two — which
    // is precisely why the counter cannot be reconciled from badges alone.
    const degree = crossTeamDegreeByNode(CHAIN, THREE_TEAMS)
    expect(degree.get('a1')).toBe(1)
  })

  it('counts every crossing as hidden when the cross-team toggle is off', () => {
    // Reachable with no team filter at all, from the checkbox sitting directly
    // beside the counter: all three nodes visible, yet no curve is drawn.
    const visible = new Set(['a1', 'b1', 'c1'])
    expect(hiddenCrossTeamCount(CHAIN, visible, THREE_TEAMS, { showCrossTeam: false })).toBe(2)
  })

  it('counts crossings whose edge kind is unchecked', () => {
    const visible = new Set(['a1', 'b1', 'c1'])
    const mixed = [edge('a1', 'b1', { kind: 'delegation' }), edge('b1', 'c1', { kind: 'call' })]
    expect(hiddenCrossTeamCount(mixed, visible, THREE_TEAMS, {
      visibleKinds: new Set<TopologyEdge['kind']>(['delegation']),
    })).toBe(1)
  })

  it('is zero when the whole fleet is drawn', () => {
    const visible = new Set(['a1', 'b1', 'c1'])
    expect(hiddenCrossTeamCount(CHAIN, visible, THREE_TEAMS)).toBe(0)
  })

  it('ignores intra-team edges entirely', () => {
    const intra = [edge('a1', 'a1'), ...CHAIN]
    expect(hiddenCrossTeamCount(intra, new Set(['a1', 'b1', 'c1']), THREE_TEAMS)).toBe(0)
  })
})

describe('isEdgeDrawn', () => {
  const NODES3: readonly TopologyNode[] = [node('a1', 'alpha'), node('b1', 'beta')]
  const T = teamById(NODES3)
  const ALL = new Set(['a1', 'b1'])

  it('draws an ordinary edge with both endpoints on screen', () => {
    expect(isEdgeDrawn(edge('a1', 'b1'), ALL, T)).toBe(true)
  })

  it('drops an edge whose far endpoint the team filter removed', () => {
    expect(isEdgeDrawn(edge('a1', 'b1'), new Set(['a1']), T)).toBe(false)
  })

  it('drops an unchecked edge kind', () => {
    expect(isEdgeDrawn(edge('a1', 'b1', { kind: 'call' }), ALL, T, {
      visibleKinds: new Set<TopologyEdge['kind']>(['delegation']),
    })).toBe(false)
  })

  it('drops a cross-team edge when the toggle is off, but keeps intra-team ones', () => {
    expect(isEdgeDrawn(edge('a1', 'b1'), ALL, T, { showCrossTeam: false })).toBe(false)
    const intra = teamById([node('a1', 'alpha'), node('a2', 'alpha')])
    expect(isEdgeDrawn(edge('a1', 'a2'), new Set(['a1', 'a2']), intra, { showCrossTeam: false })).toBe(true)
  })

  it('drops a self-edge, which has no geometry', () => {
    expect(isEdgeDrawn(edge('a1', 'a1'), ALL, T)).toBe(false)
  })
})
