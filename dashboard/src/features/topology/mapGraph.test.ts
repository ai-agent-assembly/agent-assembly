import { describe, expect, it } from 'vitest'
import { mapTopologyGraph } from './mapGraph'
import type { components } from '../../api/generated/schema'

type ApiGraph = components['schemas']['TopologyGraphResponse']

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

  it('passes the registry runtime status through and maps team_id to team', () => {
    const graph: ApiGraph = {
      nodes: [node({ status: 'suspended', team_id: 'ops' }), node({ id: 'b', status: 'deregistered', team_id: null })],
      edges: [],
    }
    const { nodes } = mapTopologyGraph(graph)
    expect(nodes[0]).toMatchObject({ status: 'suspended', team: 'ops' })
    // A null team_id collapses to the empty (ungrouped) team bucket.
    expect(nodes[1]).toMatchObject({ status: 'deregistered', team: '' })
  })

  it('defaults owner / policyCount / budget to neutral placeholders when absent', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node()], edges: [] })
    expect(nodes[0]).toMatchObject({ owner: '', policyCount: 0, budgetSpend: 0, budgetLimit: 0 })
  })

  it('carries live owner / policy_count / budget through to the view model (AAASM-5045)', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [node({ owner: 'platform-team', policy_count: 3, budget: { spend_usd: 4.1, limit_usd: 100 } })],
      edges: [],
    })
    expect(nodes[0]).toMatchObject({ owner: 'platform-team', policyCount: 3, budgetSpend: 4.1, budgetLimit: 100 })
  })

  it('keeps the budget-limit placeholder when the limit is null (no misleading ratio)', () => {
    const { nodes } = mapTopologyGraph({
      nodes: [node({ owner: null, policy_count: 0, budget: { spend_usd: 2.5, limit_usd: null } })],
      edges: [],
    })
    expect(nodes[0]).toMatchObject({ owner: '', budgetSpend: 2.5, budgetLimit: 0 })
  })

  it('drops an unrecognised mode to undefined so the badge stays hidden', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node({ mode: 'gibberish' })], edges: [] })
    expect(nodes[0].mode).toBeUndefined()
  })

  it('null trust maps to null (renders the no-data state, not a misleading 0)', () => {
    const { nodes } = mapTopologyGraph({ nodes: [node({ trust: null })], edges: [] })
    expect(nodes[0].trust).toBeNull()
  })

  it('keeps delegation and call edges and drops any other kind', () => {
    const graph: ApiGraph = {
      nodes: [],
      edges: [
        { source: 'a', target: 'b', kind: 'delegation' },
        { source: 'b', target: 'c', kind: 'call' },
        { source: 'c', target: 'd', kind: 'messages' },
      ],
    }
    const { edges } = mapTopologyGraph(graph)
    expect(edges).toEqual([
      { source: 'a', target: 'b', kind: 'delegation' },
      { source: 'b', target: 'c', kind: 'call' },
    ])
  })

  it('tolerates a partial payload missing nodes / edges arrays', () => {
    const { nodes, edges } = mapTopologyGraph({} as ApiGraph)
    expect(nodes).toEqual([])
    expect(edges).toEqual([])
  })
})
