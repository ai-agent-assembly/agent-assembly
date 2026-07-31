import { describe, expect, it } from 'vitest'
import { mapTopologyGraph } from './mapGraph'
import { UNCLAIMED_TEAM } from './unclaimed'
import type { components } from '../../api/generated/schema'

// Only the nodes + edges subset the mapper reads — `unclaimed_observable`
// (AAASM-5183) is not consumed by mapTopologyGraph.
type ApiGraph = Pick<components['schemas']['TopologyGraphResponse'], 'nodes' | 'edges'>

function node(over: Partial<components['schemas']['AgentNode']> = {}): components['schemas']['AgentNode'] {
  return { id: 'a', name: 'agent', depth: 0, status: 'active', mode: 'enforce', flagged: false, trust: null, ...over }
}

describe('mapTopologyGraph', () => {
  it('carries the live mode / flagged / trust badges through to the view model', () => {
    const graph: ApiGraph = {
      nodes: [node({ id: 'x', mode: 'shadow', flagged: true, trust: 87 })],
      edges: [],
    }
    const { nodes } = mapTopologyGraph(graph)
    expect(nodes[0]).toMatchObject({ id: 'x', mode: 'shadow', flagged: true, trust: 87 })
  })

  it('joins the trust rollup onto nodes, overriding the endpoint placeholder', () => {
    // AAASM-5083: the endpoint sends `trust: null`; the real score arrives via
    // the analytics rollup and wins. A cold-start `null` in the lookup still
    // overrides (rendered `—`), and an agent absent from the lookup keeps its
    // own value — never coerced to 0.
    const graph: ApiGraph = {
      nodes: [node({ id: 'scored', trust: null }), node({ id: 'cold', trust: null }), node({ id: 'absent', trust: null })],
      edges: [],
    }
    const trust = new Map<string, number | null>([
      ['scored', 78],
      ['cold', null],
    ])
    const { nodes } = mapTopologyGraph(graph, trust)
    expect(nodes.find((n) => n.id === 'scored')?.trust).toBe(78)
    expect(nodes.find((n) => n.id === 'cold')?.trust).toBeNull()
    expect(nodes.find((n) => n.id === 'absent')?.trust).toBeNull()
  })

  it('leaves node trust untouched when no trust lookup is supplied', () => {
    const graph: ApiGraph = { nodes: [node({ id: 'x', trust: 91 })], edges: [] }
    expect(mapTopologyGraph(graph).nodes[0].trust).toBe(91)
  })

  it('passes the registry runtime status through and maps team_id to team', () => {
    const graph: ApiGraph = {
      nodes: [node({ status: 'suspended', team_id: 'ops' }), node({ id: 'b', status: 'deregistered', team_id: null })],
      edges: [],
    }
    const { nodes } = mapTopologyGraph(graph)
    expect(nodes[0]).toMatchObject({ status: 'suspended', team: 'ops' })
    // A null team_id joins the named unclaimed group — never the empty string,
    // which downstream consumers read as a team whose name happens to be blank
    // (AAASM-5184).
    expect(nodes[1]).toMatchObject({ status: 'deregistered', team: UNCLAIMED_TEAM })
    expect(nodes[1].team).not.toBe('')
  })

  it('treats a blank team_id as unclaimed, not as a team named ""', () => {
    // The wire nullability is `string | null`, but `isOrphanAgent` — the
    // definition this defers to — counts `''` as an absence too. Were that not
    // honoured here, a blank id would slip through as a real team key and
    // reintroduce the unlabelled cluster from the other direction.
    const graph: ApiGraph = { nodes: [node({ id: 'blank', team_id: '' })], edges: [] }
    expect(mapTopologyGraph(graph).nodes[0].team).toBe(UNCLAIMED_TEAM)
  })

  it('treats a whitespace-only team_id as unclaimed, matching the gateway', () => {
    // The registry stores `Some("   ")` — `validate_tenant_id` (AAASM-4190)
    // rejects control characters only — and `aa-api`'s `team_of` folds it to no
    // team (AAASM-5182). Admitting it here as a team key drew the nameless
    // cluster again and had the dashboard contradict the gateway about one
    // agent (AAASM-5184).
    const graph: ApiGraph = { nodes: [node({ id: 'ws', team_id: '   ' })], edges: [] }
    expect(mapTopologyGraph(graph).nodes[0].team).toBe(UNCLAIMED_TEAM)
  })

  it('maps an absent owner / policyCount / budget to their honest placeholders', () => {
    // AAASM-5106 / ADR 0024 — an absent `policy_count` maps to `null` ("unknown"),
    // not `0`: the backend now emits `null` when no cascade is loaded, and a `0`
    // would read as "no policies apply" while the primary slot is enforcing.
    // owner falls back to '' and budget spend to 0 (both real neutral defaults);
    // budgetLimit stays null (unconfigured).
    const { nodes } = mapTopologyGraph({ nodes: [node()], edges: [] })
    expect(nodes[0]).toMatchObject({ owner: '', policyCount: null, budgetSpend: 0, budgetLimit: null })
  })

  it('carries live owner / policy_count / budget through to the view model (AAASM-5045)', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [node({ owner: 'platform-team', policy_count: 3, budget: { spend_usd: 4.1, limit_usd: 100 } })],
      edges: [],
    })
    expect(nodes[0]).toMatchObject({ owner: 'platform-team', policyCount: 3, budgetSpend: 4.1, budgetLimit: 100 })
  })

  // AAASM-5135: a null `limit_usd` means "no limit is configured", which is not
  // the same statement as "the limit is $0" — the latter reads as a budget that
  // is fully burnt at any spend at all. The absence has to survive the mapper.
  it('keeps a null budget limit null rather than collapsing it to 0', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [node({ owner: null, policy_count: 0, budget: { spend_usd: 2.5, limit_usd: null } })],
      edges: [],
    })
    expect(nodes[0]).toMatchObject({ owner: '', budgetSpend: 2.5, budgetLimit: null })
    expect(nodes[0].budgetLimit).not.toBe(0)
  })

  // A real, configured limit of zero is a different fact from an absent one, and
  // the mapper must not merge the two — `?? null` would swallow a genuine 0 if
  // it were written as a falsy check.
  it('distinguishes a configured $0 limit from an unconfigured one', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [node({ budget: { spend_usd: 0, limit_usd: 0 } })],
      edges: [],
    })
    expect(nodes[0].budgetLimit).toBe(0)
  })

  it('drops an unrecognised mode to undefined so the badge stays hidden', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node({ mode: 'gibberish' })], edges: [] })
    expect(nodes[0].mode).toBeUndefined()
  })

  it('null trust maps to null (renders the no-data state, not a misleading 0)', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node({ trust: null })], edges: [] })
    expect(nodes[0].trust).toBeNull()
  })

  it('keeps all six edge kinds and carries the cross-team flag (AAASM-5099)', () => {
    const graph: ApiGraph = {
      nodes: [],
      edges: [
        { source: 'a', target: 'b', kind: 'delegation', cross_team: false },
        { source: 'b', target: 'c', kind: 'call', cross_team: false },
        { source: 'c', target: 'd', kind: 'reads', cross_team: false },
        { source: 'd', target: 'e', kind: 'writes', cross_team: false },
        { source: 'e', target: 'f', kind: 'approves', cross_team: false },
        { source: 'f', target: 'g', kind: 'messages', cross_team: true },
      ],
    }
    const { edges } = mapTopologyGraph(graph)
    expect(edges.map((e) => e.kind)).toEqual(['delegation', 'call', 'reads', 'writes', 'approves', 'messages'])
    expect(edges[5]).toEqual({ source: 'f', target: 'g', kind: 'messages', crossTeam: true })
    expect(edges[0].crossTeam).toBe(false)
  })

  it('drops a kind the view model does not know so TopologyEdge stays sound', () => {
    const graph = {
      nodes: [],
      edges: [
        { source: 'a', target: 'b', kind: 'delegation', cross_team: false },
        { source: 'c', target: 'd', kind: 'observes', cross_team: false },
      ],
    } as unknown as ApiGraph
    const { edges } = mapTopologyGraph(graph)
    expect(edges).toHaveLength(1)
    expect(edges[0].kind).toBe('delegation')
  })

  it('maps the policy-inheritance chain onto the view model (AAASM-5099)', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [
        node({
          effective_permissions: {
            chain: [
              { tier: 'global', scope: 'global', policies: ['baseline'] },
              { tier: 'team', scope: 'team:platform', policies: [] },
            ],
            allow: ['file_read'],
            deny: ['terminal_exec'],
            allow_restricted: true,
            cascade_loaded: true,
          },
        }),
      ],
      edges: [],
    })
    expect(nodes[0].effectivePermissions).toEqual({
      chain: [
        { tier: 'global', scope: 'global', policies: ['baseline'] },
        { tier: 'team', scope: 'team:platform', policies: [] },
      ],
      allow: ['file_read'],
      deny: ['terminal_exec'],
      allowRestricted: true,
      cascadeLoaded: true,
    })
  })

  it('leaves the chain null when the node carries none (no fabricated empty chain)', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node()], edges: [] })
    expect(nodes[0].effectivePermissions).toBeNull()
  })

  it('tolerates a partial payload missing nodes / edges arrays', () => {
    const { nodes, edges } = mapTopologyGraph({} as ApiGraph)
    expect(nodes).toEqual([])
    expect(edges).toEqual([])
  })
})
