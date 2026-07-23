import { describe, expect, it } from 'vitest'
import { computeHierarchy, detectDelegationCycles } from './hierarchy'
import type { TopologyEdge, TopologyNode } from './types'

function node(id: string, overrides: Partial<TopologyNode> = {}): TopologyNode {
  return {
    id,
    name: id,
    status: 'active',
    team: 'a',
    owner: 'o',
    policyCount: 0,
    budgetSpend: 0,
    budgetLimit: 10,
    ...overrides,
  }
}

const del = (source: string, target: string): TopologyEdge => ({ source, target, kind: 'delegation' })
const call = (source: string, target: string): TopologyEdge => ({ source, target, kind: 'call' })

describe('detectDelegationCycles', () => {
  it('flags every node on a delegation cycle', () => {
    // a → b → c → a
    const cycle = detectDelegationCycles([del('a', 'b'), del('b', 'c'), del('c', 'a')])
    expect(cycle).toEqual(new Set(['a', 'b', 'c']))
  })

  it('returns an empty set for an acyclic tree', () => {
    // root → {b, c}; c → d
    const cycle = detectDelegationCycles([del('root', 'b'), del('root', 'c'), del('c', 'd')])
    expect(cycle.size).toBe(0)
  })

  it('flags a self-delegating node', () => {
    const cycle = detectDelegationCycles([del('a', 'a')])
    expect(cycle).toEqual(new Set(['a']))
  })

  it('ignores non-delegation edges — a cycle made of `call` edges is not a delegation cycle', () => {
    const cycle = detectDelegationCycles([call('a', 'b'), call('b', 'a')])
    expect(cycle.size).toBe(0)
  })

  it('flags only the cyclic component, leaving an attached acyclic tail out', () => {
    // b → c → b is a cycle; a → b and c → d are acyclic attachments
    const cycle = detectDelegationCycles([del('a', 'b'), del('b', 'c'), del('c', 'b'), del('c', 'd')])
    expect(cycle).toEqual(new Set(['b', 'c']))
  })
})

describe('computeHierarchy', () => {
  it('assigns depth and roots for a delegation tree', () => {
    const nodes = [node('root'), node('b'), node('c'), node('d')]
    const edges = [del('root', 'b'), del('root', 'c'), del('c', 'd')]
    const { depthById, rootIds } = computeHierarchy(nodes, edges)

    expect(rootIds).toEqual(new Set(['root']))
    expect(depthById.get('root')).toBe(0)
    expect(depthById.get('b')).toBe(1)
    expect(depthById.get('c')).toBe(1)
    expect(depthById.get('d')).toBe(2)
  })

  it('treats a disconnected node as a depth-0 root', () => {
    const nodes = [node('root'), node('child'), node('lonely')]
    const edges = [del('root', 'child')]
    const { depthById, rootIds } = computeHierarchy(nodes, edges)

    expect(rootIds).toEqual(new Set(['root', 'lonely']))
    expect(depthById.get('lonely')).toBe(0)
    expect(depthById.get('child')).toBe(1)
  })

  it('does not count a `call` edge as a delegation parent (target stays a root)', () => {
    const nodes = [node('a'), node('b')]
    const edges = [call('a', 'b')]
    const { rootIds, depthById } = computeHierarchy(nodes, edges)

    expect(rootIds).toEqual(new Set(['a', 'b']))
    expect(depthById.get('b')).toBe(0)
  })

  it('gives shortest-path depth when a node is reachable by two paths', () => {
    // root → mid → leaf and root → leaf: leaf's shortest depth is 1
    const nodes = [node('root'), node('mid'), node('leaf')]
    const edges = [del('root', 'mid'), del('mid', 'leaf'), del('root', 'leaf')]
    const { depthById } = computeHierarchy(nodes, edges)

    expect(depthById.get('leaf')).toBe(1)
  })

  it('falls back to depth 0 for nodes only reachable through a rootless cycle', () => {
    // a → b → a is a pure cycle with no external root
    const nodes = [node('a'), node('b')]
    const edges = [del('a', 'b'), del('b', 'a')]
    const { depthById, rootIds } = computeHierarchy(nodes, edges)

    expect(rootIds.size).toBe(0)
    expect(depthById.get('a')).toBe(0)
    expect(depthById.get('b')).toBe(0)
  })
})
