/**
 * The force simulation must survive a metrics-only payload update (AAASM-5136).
 *
 * The 5s poll hands `TopologyGraph` a brand-new `nodes` array whenever any
 * agent's spend or status moves. Rebuilding the simulation on that restarts it
 * at `alpha(1)` over freshly-constructed, un-positioned nodes: the whole graph
 * re-scatters and re-settles every five seconds, moving click targets under the
 * operator. The mechanism pre-existed on focus/mutation refetches; polling made
 * it continuous.
 *
 * This is asserted by counting **how many simulations are constructed**, not by
 * comparing settled card positions. Position comparison cannot detect the bug:
 * d3's force simulation is deterministic, so a full rebuild re-initialises to
 * the same phyllotaxis and converges back to the same final layout — identical
 * "before" and "after" transforms while the graph visibly scattered in between.
 */
import { render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'

const sim = vi.hoisted(() => ({ count: 0 }))

vi.mock('d3-force', async (importOriginal) => {
  const actual = await importOriginal<typeof import('d3-force')>()
  return {
    ...actual,
    forceSimulation: (...args: Parameters<typeof actual.forceSimulation>) => {
      sim.count += 1
      return actual.forceSimulation(...args)
    },
  }
})

const { TopologyGraph } = await import('./TopologyGraph')

const BASE: TopologyNode[] = [
  { id: 's1', name: 'one', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  { id: 's2', name: 'two', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 2, budgetLimit: 10 },
  { id: 't1', name: 'three', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 3, budgetLimit: 10 },
]
const EDGES: TopologyEdge[] = [{ source: 's1', target: 't1', kind: 'delegation' }]

describe('TopologyGraph — simulation stability across payload updates', () => {
  beforeEach(() => { sim.count = 0 })

  it('does not rebuild the simulation when only the metrics change', () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    const afterMount = sim.count
    expect(afterMount).toBeGreaterThan(0)

    // A new array of new objects — exactly what `mapTopologyGraph` produces on
    // every poll once any figure has moved.
    rerender(<TopologyGraph nodes={BASE.map(n => ({ ...n, budgetSpend: n.budgetSpend + 1 }))} edges={[...EDGES]} />)
    rerender(<TopologyGraph nodes={BASE.map(n => ({ ...n, budgetSpend: n.budgetSpend + 2 }))} edges={[...EDGES]} />)

    expect(sim.count).toBe(afterMount)
  })

  it('does not rebuild when a status changes', () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    const afterMount = sim.count
    rerender(
      <TopologyGraph
        nodes={BASE.map(n => (n.id === 's1' ? { ...n, status: 'suspended' as const } : n))}
        edges={EDGES}
      />,
    )
    expect(sim.count).toBe(afterMount)
  })

  it('does rebuild when the set of agents actually changes', () => {
    // A new agent has no position yet, so a re-layout there is correct — only
    // metrics-only updates are exempt.
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    const afterMount = sim.count
    rerender(
      <TopologyGraph
        nodes={[...BASE, { id: 'n4', name: 'four', status: 'active', team: 'gamma', owner: 'c', policyCount: 1, budgetSpend: 1, budgetLimit: 10 }]}
        edges={EDGES}
      />,
    )
    expect(sim.count).toBeGreaterThan(afterMount)
  })

  it('does rebuild when an edge appears', () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    const afterMount = sim.count
    rerender(<TopologyGraph nodes={BASE} edges={[...EDGES, { source: 's2', target: 't1', kind: 'call' }]} />)
    expect(sim.count).toBeGreaterThan(afterMount)
  })

  // The other half of the guarantee: "stop re-scattering" must not have become
  // "stop updating". Card data is read live rather than from the node object the
  // simulation closed over at build time.
  it('still shows the new figures even though the layout did not move', async () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    await waitFor(() => expect(screen.getAllByTestId('topology-node-budget')).toHaveLength(3))

    rerender(<TopologyGraph nodes={BASE.map(n => ({ ...n, budgetSpend: 7.5 }))} edges={EDGES} />)

    for (const budget of screen.getAllByTestId('topology-node-budget')) {
      expect(budget.textContent).toContain('$7.5')
    }
  })

  it('still reflects a status change on the card', () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    rerender(
      <TopologyGraph
        nodes={BASE.map(n => (n.id === 's1' ? { ...n, status: 'suspended' as const } : n))}
        edges={EDGES}
      />,
    )
    const suspended = screen.getAllByTestId('topology-node').filter(g => g.getAttribute('data-status') === 'suspended')
    expect(suspended).toHaveLength(1)
  })

  it('still reflects a newly-unconfigured budget limit', () => {
    const { rerender } = render(<TopologyGraph nodes={BASE} edges={EDGES} />)
    rerender(<TopologyGraph nodes={BASE.map(n => ({ ...n, budgetLimit: null }))} edges={EDGES} />)
    for (const budget of screen.getAllByTestId('topology-node-budget')) {
      expect(budget).toHaveAttribute('data-truth-state', 'unconfigured')
    }
  })
})
