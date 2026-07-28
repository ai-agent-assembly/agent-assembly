import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TopologyGraph } from './TopologyGraph'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'
import { UNCLAIMED_TEAM } from '../../features/topology/unclaimed'

const NODES: TopologyNode[] = [
  // ratio 0.1 → small
  { id: 'n1', name: 'support-1', status: 'active', team: 'a', owner: 'alice', policyCount: 2, budgetSpend: 1, budgetLimit: 10 },
  // ratio 0.4 → small
  { id: 'n2', name: 'support-2', status: 'idle', team: 'a', owner: 'alice', policyCount: 2, budgetSpend: 4, budgetLimit: 10 },
  // ratio 0.7 → medium
  { id: 'n3', name: 'analyst', status: 'active', team: 'b', owner: 'bob', policyCount: 3, budgetSpend: 7, budgetLimit: 10 },
  // ratio 0.8 → medium (inclusive upper)
  { id: 'n4', name: 'audit', status: 'idle', team: 'b', owner: 'bob', policyCount: 1, budgetSpend: 8, budgetLimit: 10 },
  // ratio 0.95 → large; also error
  { id: 'n5', name: 'deploy', status: 'error', team: 'c', owner: 'carol', policyCount: 0, budgetSpend: 9.5, budgetLimit: 10 },
]

describe('TopologyGraph', () => {
  it('renders one <g data-testid="topology-node"> per node', () => {
    render(<TopologyGraph nodes={NODES} edges={[]} />)
    expect(screen.getAllByTestId('topology-node')).toHaveLength(NODES.length)
  })

  it('mirrors status onto data-status for each node', () => {
    render(<TopologyGraph nodes={NODES} edges={[]} />)
    const cards = screen.getAllByTestId('topology-node')
    expect(cards[0]).toHaveAttribute('data-status', 'active')
    expect(cards[1]).toHaveAttribute('data-status', 'idle')
    expect(cards[2]).toHaveAttribute('data-status', 'active')
    expect(cards[3]).toHaveAttribute('data-status', 'idle')
    expect(cards[4]).toHaveAttribute('data-status', 'error')
  })

  it('buckets each node by budgetSpend/budgetLimit into small / medium / large', () => {
    render(<TopologyGraph nodes={NODES} edges={[]} />)
    const cards = screen.getAllByTestId('topology-node')
    expect(cards[0]).toHaveAttribute('data-size-bucket', 'small')  // 0.1
    expect(cards[1]).toHaveAttribute('data-size-bucket', 'small')  // 0.4
    expect(cards[2]).toHaveAttribute('data-size-bucket', 'medium') // 0.7
    expect(cards[3]).toHaveAttribute('data-size-bucket', 'medium') // 0.8 (inclusive upper)
    expect(cards[4]).toHaveAttribute('data-size-bucket', 'large')  // 0.95
  })

  it('handles budgetLimit=0 gracefully (no division by zero, defaults to small)', () => {
    const edge: TopologyNode[] = [
      { id: 'edge', name: 'noisy', status: 'idle', team: 'a', owner: 'alice', policyCount: 0, budgetSpend: 0, budgetLimit: 0 },
    ]
    render(<TopologyGraph nodes={edge} edges={[]} />)
    expect(screen.getByTestId('topology-node')).toHaveAttribute('data-size-bucket', 'small')
  })

  it('renders the node name, framework, and budget summary', () => {
    const single: TopologyNode[] = [
      { id: 'x', name: 'long-agent-name-truncated', status: 'active', team: 'a', owner: 'alice', policyCount: 1, budgetSpend: 4.1, budgetLimit: 10, framework: 'langgraph' },
    ]
    render(<TopologyGraph nodes={single} edges={[]} />)
    const card = screen.getByTestId('topology-node')
    // Name truncated to 14 chars + ellipsis.
    expect(card.textContent).toContain('long-agent-na…')
    expect(card.textContent).toContain('langgraph')
    expect(card.textContent).toContain('$4.1 / $10')
  })

  it('exposes role=button and tabIndex=0 only when onNodeClick is provided', () => {
    const { rerender } = render(<TopologyGraph nodes={NODES.slice(0, 1)} edges={[]} />)
    expect(screen.getByTestId('topology-node')).not.toHaveAttribute('role')
    expect(screen.getByTestId('topology-node')).not.toHaveAttribute('tabindex')

    rerender(<TopologyGraph nodes={NODES.slice(0, 1)} edges={[]} onNodeClick={() => {}} />)
    expect(screen.getByTestId('topology-node')).toHaveAttribute('role', 'button')
    expect(screen.getByTestId('topology-node')).toHaveAttribute('tabindex', '0')
  })

  it('fires onNodeClick with the right node on click + Enter + Space', async () => {
    const onClick = vi.fn()
    render(<TopologyGraph nodes={[NODES[2]]} edges={[]} onNodeClick={onClick} />)
    const node = screen.getByTestId('topology-node')

    await userEvent.click(node)
    expect(onClick).toHaveBeenLastCalledWith(NODES[2])

    node.focus()
    await userEvent.keyboard('{Enter}')
    expect(onClick).toHaveBeenCalledTimes(2)
    await userEvent.keyboard(' ')
    expect(onClick).toHaveBeenCalledTimes(3)
    // Same node every time.
    expect(onClick.mock.calls.every(call => call[0].id === 'n3')).toBe(true)
  })

  it('does not fire onNodeClick when callback is omitted', async () => {
    render(<TopologyGraph nodes={[NODES[0]]} edges={[]} />)
    const node = screen.getByTestId('topology-node')
    // With no callback the node must stay non-interactive: the click handler
    // is never attached, so it carries neither role=button nor a tab stop.
    await userEvent.click(node)
    expect(node).not.toHaveAttribute('role')
    expect(node).not.toHaveAttribute('tabindex')
  })

  // ── Team grouping (AAASM-1339) ─────────────────────────────────────────────
  describe('team grouping', () => {
    const TWO_TEAMS: TopologyNode[] = [
      { id: 'sa1', name: 'sa1', status: 'active', team: 'support',   owner: 'alice', policyCount: 2, budgetSpend: 1,   budgetLimit: 10 },
      { id: 'sa2', name: 'sa2', status: 'idle',   team: 'support',   owner: 'alice', policyCount: 2, budgetSpend: 2,   budgetLimit: 10 },
      { id: 'sa3', name: 'sa3', status: 'active', team: 'support',   owner: 'alice', policyCount: 2, budgetSpend: 4,   budgetLimit: 10 },
      // Analytics team sits at 95% → danger
      { id: 'an1', name: 'an1', status: 'active', team: 'analytics', owner: 'bob',   policyCount: 1, budgetSpend: 5,   budgetLimit: 5  },
      { id: 'an2', name: 'an2', status: 'idle',   team: 'analytics', owner: 'bob',   policyCount: 1, budgetSpend: 3.5, budgetLimit: 5  },
      { id: 'an3', name: 'an3', status: 'error',  team: 'analytics', owner: 'bob',   policyCount: 1, budgetSpend: 1,   budgetLimit: 5  },
    ]

    it('renders one team-cluster <g> per team with data-team attribute', () => {
      render(<TopologyGraph nodes={TWO_TEAMS} edges={[]} />)
      const clusters = screen.getAllByTestId('team-cluster')
      expect(clusters).toHaveLength(2)
      const teams = clusters.map(c => c.dataset.team).sort()
      expect(teams).toEqual(['analytics', 'support'])
    })

    it('renders one TeamBudgetBar per cluster with aggregated spend/limit', () => {
      render(<TopologyGraph nodes={TWO_TEAMS} edges={[]} />)
      const bars = screen.getAllByTestId('team-budget-bar')
      expect(bars).toHaveLength(2)

      const support = bars.find(b => b.dataset.team === 'support')!
      const analytics = bars.find(b => b.dataset.team === 'analytics')!

      // support: spent 1+2+4=7, limit 10+10+10=30 → 23% → ok
      expect(support).toHaveAttribute('data-threshold-bucket', 'ok')
      expect(support).toHaveTextContent('$7 / $30 · 23%')

      // analytics: spent 5+3.5+1=9.5, limit 5+5+5=15 → 63% → ok (below 80%)
      expect(analytics).toHaveAttribute('data-threshold-bucket', 'ok')
      expect(analytics).toHaveTextContent('63%')
    })

    it('switches a cluster bar to danger when team spend ≥ 95% of limit', () => {
      const overspent: TopologyNode[] = [
        { id: 'a', name: 'a', status: 'active', team: 'team-x', owner: 'a', policyCount: 0, budgetSpend: 9.6, budgetLimit: 10 },
        { id: 'b', name: 'b', status: 'idle',   team: 'team-x', owner: 'a', policyCount: 0, budgetSpend: 0,   budgetLimit: 0  },
      ]
      render(<TopologyGraph nodes={overspent} edges={[]} />)
      const bar = screen.getByTestId('team-budget-bar')
      expect(bar).toHaveAttribute('data-team', 'team-x')
      // 9.6 / 10 = 96% → danger
      expect(bar).toHaveAttribute('data-threshold-bucket', 'danger')
    })

    it('renders a team-cluster-label per cluster with the team name', () => {
      render(<TopologyGraph nodes={TWO_TEAMS} edges={[]} />)
      const labels = screen.getAllByTestId('team-cluster-label')
      expect(labels).toHaveLength(2)
      const texts = labels.map(l => l.textContent).sort()
      expect(texts).toEqual(['analytics', 'support'])
    })
  })

  // ── Relationship edges (AAASM-5019) ────────────────────────────────────────
  // The graph must actually draw the edges between agents: one <path> per edge,
  // styled per kind, with cross-team edges flagged so they render as curves.
  describe('edges', () => {
    const EDGE_NODES: TopologyNode[] = [
      { id: 'p1', name: 'planner', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
      { id: 'w1', name: 'worker-1', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 2, budgetLimit: 10 },
      { id: 'w2', name: 'worker-2', status: 'idle', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 3, budgetLimit: 10 },
      { id: 'x1', name: 'x-caller', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ]
    // 3 intra-team delegations + 1 cross-team call.
    const EDGE_EDGES: TopologyEdge[] = [
      { source: 'p1', target: 'w1', kind: 'delegation' },
      { source: 'p1', target: 'w2', kind: 'delegation' },
      { source: 'w1', target: 'w2', kind: 'call' },
      { source: 'p1', target: 'x1', kind: 'call' },
    ]

    it('renders one <path data-testid="topology-edge"> per edge', () => {
      render(<TopologyGraph nodes={EDGE_NODES} edges={EDGE_EDGES} />)
      expect(screen.getAllByTestId('topology-edge')).toHaveLength(EDGE_EDGES.length)
    })

    it('mirrors each edge kind onto data-kind and a per-kind class', () => {
      render(<TopologyGraph nodes={EDGE_NODES} edges={EDGE_EDGES} />)
      const paths = screen.getAllByTestId('topology-edge')
      const kinds = paths.map(p => p.getAttribute('data-kind'))
      expect(kinds).toEqual(['delegation', 'delegation', 'call', 'call'])
      // Per-kind styling hook is present so the CSS token can colour each line.
      expect(paths[0]).toHaveClass('topology-edge--delegation')
      expect(paths[2]).toHaveClass('topology-edge--call')
    })

    it('flags only cross-team edges and draws them as curves', () => {
      render(<TopologyGraph nodes={EDGE_NODES} edges={EDGE_EDGES} />)
      const paths = screen.getAllByTestId('topology-edge')
      // p1→x1 (alpha→beta) is the only cross-team edge.
      const cross = paths.filter(p => p.getAttribute('data-cross-team') === 'true')
      expect(cross).toHaveLength(1)
      // Cross-team edges bow out along a quadratic curve (command "Q");
      // intra-team edges are straight lines (command "L").
      expect(cross[0].getAttribute('d')).toContain('Q')
      const intra = paths.filter(p => p.getAttribute('data-cross-team') !== 'true')
      for (const p of intra) expect(p.getAttribute('d')).toContain('L')
    })

    it('attaches a per-kind arrowhead marker to each edge', () => {
      render(<TopologyGraph nodes={EDGE_NODES} edges={EDGE_EDGES} />)
      const paths = screen.getAllByTestId('topology-edge')
      expect(paths[0]).toHaveAttribute('marker-end', 'url(#topo-arrow-delegation)')
      expect(paths[2]).toHaveAttribute('marker-end', 'url(#topo-arrow-call)')
    })

    it('renders no edge paths when there are no edges', () => {
      render(<TopologyGraph nodes={EDGE_NODES} edges={[]} />)
      expect(screen.queryByTestId('topology-edge')).toBeNull()
    })
  })

  // ── Collision (AAASM-5018) ─────────────────────────────────────────────────
  // The per-team forceX/forceY pull every same-team card toward one center, so
  // without a collision force the cards stack on top of each other. Assert the
  // simulation settles with no two same-team cards overlapping.
  describe('collision', () => {
    // Card dims by size bucket (mirrors SIZE_VARIANT in TopologyGraph.tsx).
    const CARD = { small: { w: 76, h: 44 }, medium: { w: 96, h: 56 }, large: { w: 116, h: 68 } }

    function cardRect(node: Element) {
      const m = /translate\(([-\d.]+),\s*([-\d.]+)\)/.exec(node.getAttribute('transform') ?? '')
      const x = Number(m?.[1] ?? 0)
      const y = Number(m?.[2] ?? 0)
      const bucket = node.getAttribute('data-size-bucket') as keyof typeof CARD
      const { w, h } = CARD[bucket]
      return { x, y, w, h }
    }

    function overlaps(a: ReturnType<typeof cardRect>, b: ReturnType<typeof cardRect>) {
      return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y
    }

    const SAME_TEAM: TopologyNode[] = Array.from({ length: 6 }, (_, i) => ({
      id: `t${i}`,
      name: `agent-${i}`,
      status: 'active',
      team: 'clustered',
      owner: 'alice',
      policyCount: 1,
      budgetSpend: 1,
      budgetLimit: 10,
    }))

    it('settles with no two same-team cards overlapping', async () => {
      render(<TopologyGraph nodes={SAME_TEAM} edges={[]} width={800} height={500} />)
      await waitFor(
        () => {
          const rects = screen.getAllByTestId('topology-node').map(cardRect)
          for (let i = 0; i < rects.length; i++) {
            for (let j = i + 1; j < rects.length; j++) {
              expect(overlaps(rects[i], rects[j])).toBe(false)
            }
          }
        },
        { timeout: 4000, interval: 100 },
      )
    })

    // Large cards (high budget ratio → `large` size bucket) get a bigger
    // collision radius, so the radius callback must scale the spacing with the
    // card size — exercise it with the widest bucket and assert no overlap.
    const LARGE_SAME_TEAM: TopologyNode[] = Array.from({ length: 6 }, (_, i) => ({
      id: `l${i}`,
      name: `big-${i}`,
      status: 'active',
      team: 'clustered',
      owner: 'alice',
      policyCount: 1,
      budgetSpend: 9,
      budgetLimit: 10,
    }))

    it('scales the collision radius so large cards also settle without overlap', async () => {
      render(<TopologyGraph nodes={LARGE_SAME_TEAM} edges={[]} width={800} height={500} />)
      await waitFor(
        () => {
          const cards = screen.getAllByTestId('topology-node')
          // Confirm the fixture actually drives the `large` radius branch.
          expect(cards[0].getAttribute('data-size-bucket')).toBe('large')
          const rects = cards.map(cardRect)
          for (let i = 0; i < rects.length; i++) {
            for (let j = i + 1; j < rects.length; j++) {
              expect(overlaps(rects[i], rects[j])).toBe(false)
            }
          }
        },
        { timeout: 4000, interval: 100 },
      )
    })
  })
})

describe('TopologyGraph — delegation badges & markers (AAASM-5033)', () => {
  const ROOT_AND_CHILD: TopologyNode[] = [
    { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'c', name: 'worker', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  ]
  const DELEGATION_EDGE: TopologyEdge[] = [{ source: 'r', target: 'c', kind: 'delegation' }]

  function nodeByName(name: string): HTMLElement {
    const match = screen
      .getAllByTestId('topology-node')
      .find(g => g.querySelector('.topology-node__name')?.textContent?.includes(name))
    if (!match) throw new Error(`node ${name} not found`)
    return match
  }

  it('marks the delegation root with a `root` badge and delegates with `L<depth>`', () => {
    render(<TopologyGraph nodes={ROOT_AND_CHILD} edges={DELEGATION_EDGE} />)
    const root = nodeByName('planner')
    const child = nodeByName('worker')

    expect(root).toHaveAttribute('data-root', 'true')
    expect(root).toHaveAttribute('data-depth', '0')
    expect(root.querySelector('[data-testid="topology-node-depth"]')?.textContent).toBe('root')

    expect(child).not.toHaveAttribute('data-root')
    expect(child).toHaveAttribute('data-depth', '1')
    expect(child.querySelector('[data-testid="topology-node-depth"]')?.textContent).toBe('L1')
  })

  it('marks every node on a delegation cycle with data-in-cycle and a ⟳ glyph', () => {
    const edges: TopologyEdge[] = [
      { source: 'r', target: 'c', kind: 'delegation' },
      { source: 'c', target: 'r', kind: 'delegation' },
    ]
    render(<TopologyGraph nodes={ROOT_AND_CHILD} edges={edges} />)
    for (const name of ['planner', 'worker']) {
      const g = nodeByName(name)
      expect(g).toHaveAttribute('data-in-cycle', 'true')
      expect(g.querySelector('[data-testid="topology-node-cycle"]')?.textContent).toBe('⟳')
    }
  })

  it('renders no cycle marker for an acyclic graph', () => {
    render(<TopologyGraph nodes={ROOT_AND_CHILD} edges={DELEGATION_EDGE} />)
    expect(screen.queryByTestId('topology-node-cycle')).toBeNull()
    expect(nodeByName('planner')).not.toHaveAttribute('data-in-cycle')
  })

  it('renders the enforcement-mode badge only when the node carries a mode', () => {
    const nodes: TopologyNode[] = [
      { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, mode: 'shadow' },
      { id: 'c', name: 'worker', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ]
    render(<TopologyGraph nodes={nodes} edges={DELEGATION_EDGE} />)

    const withMode = nodeByName('planner')
    expect(withMode).toHaveAttribute('data-mode', 'shadow')
    const badge = withMode.querySelector('[data-testid="topology-node-mode"]')
    // Small (low-budget) card → colour-coded glyph only, no word.
    expect(badge?.getAttribute('data-mode-label')).toBe('glyph')
    expect(badge?.textContent).toContain('◐')
    expect(badge).toHaveClass('topology-node__mode--shadow')

    const noMode = nodeByName('worker')
    expect(noMode).not.toHaveAttribute('data-mode')
    expect(noMode.querySelector('[data-testid="topology-node-mode"]')).toBeNull()
  })

  it('spells out the mode next to the glyph on a wide (high-budget) card', () => {
    const nodes: TopologyNode[] = [
      { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 9.5, budgetLimit: 10, mode: 'enforce' },
    ]
    render(<TopologyGraph nodes={nodes} edges={[]} />)
    const badge = nodeByName('planner').querySelector('[data-testid="topology-node-mode"]')
    expect(badge?.getAttribute('data-mode-label')).toBe('full')
    expect(badge?.textContent).toContain('enforce')
  })

  it('flags a policy-flagged node with data-flagged and a ⚑ name prefix', () => {
    const nodes: TopologyNode[] = [
      { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, flagged: true },
      { id: 'c', name: 'worker', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ]
    render(<TopologyGraph nodes={nodes} edges={DELEGATION_EDGE} />)

    const flagged = nodeByName('planner')
    expect(flagged).toHaveAttribute('data-flagged', 'true')
    expect(flagged.querySelector('.topology-node__name')?.textContent).toContain('⚑')

    expect(nodeByName('worker')).not.toHaveAttribute('data-flagged')
  })

  it('renders the trust badge only when the node carries a numeric trust score', () => {
    const nodes: TopologyNode[] = [
      { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, trust: 82 },
      // trust: null is the server default (no analytics source yet) — badge hidden.
      { id: 'c', name: 'worker', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, trust: null },
      // trust absent entirely — also hidden.
      { id: 'g', name: 'gofer', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ]
    render(<TopologyGraph nodes={nodes} edges={DELEGATION_EDGE} />)

    const withTrust = nodeByName('planner')
    expect(withTrust).toHaveAttribute('data-trust', '82')
    const badge = withTrust.querySelector('[data-testid="topology-node-trust"]')
    expect(badge?.textContent).toContain('82')

    const nullTrust = nodeByName('worker')
    expect(nullTrust).not.toHaveAttribute('data-trust')
    expect(nullTrust.querySelector('[data-testid="topology-node-trust"]')).toBeNull()

    const noTrust = nodeByName('gofer')
    expect(noTrust).not.toHaveAttribute('data-trust')
    expect(noTrust.querySelector('[data-testid="topology-node-trust"]')).toBeNull()
  })

  it('renders the trust badge even when the score is zero (falsy but present)', () => {
    const nodes: TopologyNode[] = [
      { id: 'r', name: 'planner', status: 'active', team: 't', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, trust: 0 },
    ]
    render(<TopologyGraph nodes={nodes} edges={[]} />)
    const node = nodeByName('planner')
    expect(node).toHaveAttribute('data-trust', '0')
    expect(node.querySelector('[data-testid="topology-node-trust"]')?.textContent).toContain('0')
  })
})

// ── Pan / zoom + filtering + selection (AAASM-5071) ──────────────────────────
describe('TopologyGraph — pan/zoom, edge filter, team select', () => {
  const NODES4: TopologyNode[] = [
    { id: 'p1', name: 'planner', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'w1', name: 'worker-1', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 2, budgetLimit: 10 },
    { id: 'x1', name: 'x-caller', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  ]
  const EDGES3: TopologyEdge[] = [
    { source: 'p1', target: 'w1', kind: 'delegation' },
    { source: 'w1', target: 'p1', kind: 'call' },
    { source: 'p1', target: 'x1', kind: 'call' }, // cross-team
  ]

  it('renders zoom controls with a 100% readout by default', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} />)
    expect(screen.getByTestId('topology-zoom-controls')).toBeInTheDocument()
    expect(screen.getByTestId('topology-zoom-readout')).toHaveTextContent('100%')
  })

  it('zoom-in / zoom-out / reset update the readout and viewport scale', async () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} />)
    const viewport = screen.getByTestId('topology-graph-viewport')
    expect(viewport.getAttribute('transform')).toContain('scale(1)')

    await userEvent.click(screen.getByTestId('topology-zoom-in'))
    expect(screen.getByTestId('topology-zoom-readout')).toHaveTextContent('120%')
    expect(viewport.getAttribute('transform')).toContain('scale(1.2)')

    await userEvent.click(screen.getByTestId('topology-zoom-reset'))
    expect(screen.getByTestId('topology-zoom-readout')).toHaveTextContent('100%')
    expect(viewport.getAttribute('transform')).toBe('translate(0 0) scale(1)')

    await userEvent.click(screen.getByTestId('topology-zoom-out'))
    expect(screen.getByTestId('topology-zoom-readout')).toHaveTextContent('83%')
  })

  it('hides edge kinds not in visibleKinds', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} visibleKinds={new Set(['delegation'])} />)
    const kinds = screen.getAllByTestId('topology-edge').map(p => p.getAttribute('data-kind'))
    expect(kinds).toEqual(['delegation'])
  })

  it('hides cross-team edges when showCrossTeam is false', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} showCrossTeam={false} />)
    const cross = screen.getAllByTestId('topology-edge').filter(p => p.getAttribute('data-cross-team') === 'true')
    expect(cross).toHaveLength(0)
  })

  // ── Widened edge kinds (AAASM-5099) ────────────────────────────────────────

  const EDGES6: TopologyEdge[] = [
    { source: 'p1', target: 'w1', kind: 'delegation', crossTeam: false },
    { source: 'w1', target: 'p1', kind: 'call', crossTeam: false },
    { source: 'p1', target: 'x1', kind: 'reads', crossTeam: true },
    { source: 'x1', target: 'p1', kind: 'writes', crossTeam: true },
    { source: 'w1', target: 'x1', kind: 'approves', crossTeam: true },
    { source: 'x1', target: 'w1', kind: 'messages', crossTeam: true },
  ]

  it('draws every one of the six relation kinds', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES6} />)
    const paths = screen.getAllByTestId('topology-edge')
    expect(paths.map(p => p.getAttribute('data-kind'))).toEqual([
      'delegation', 'call', 'reads', 'writes', 'approves', 'messages',
    ])
    // Each kind carries its own class so the CSS token applies.
    expect(paths[2]).toHaveClass('topology-edge--reads')
    expect(paths[5]).toHaveClass('topology-edge--messages')
  })

  it('filters a newly-emitted kind out via visibleKinds', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES6} visibleKinds={new Set(['reads', 'messages'])} />)
    const kinds = screen.getAllByTestId('topology-edge').map(p => p.getAttribute('data-kind'))
    expect(kinds).toEqual(['reads', 'messages'])
  })

  it("trusts the server's crossTeam flag over the endpoints' teams", () => {
    // Both endpoints are on team alpha, so the client derivation would say
    // "intra-team"; the server flag (AAASM-5099) is authoritative.
    const flagged: TopologyEdge[] = [{ source: 'p1', target: 'w1', kind: 'call', crossTeam: true }]
    render(<TopologyGraph nodes={NODES4} edges={flagged} showCrossTeam={false} />)
    expect(screen.queryAllByTestId('topology-edge')).toHaveLength(0)
  })

  it('falls back to comparing teams when the payload carries no flag', () => {
    const unflagged: TopologyEdge[] = [{ source: 'p1', target: 'x1', kind: 'call' }]
    render(<TopologyGraph nodes={NODES4} edges={unflagged} showCrossTeam={false} />)
    expect(screen.queryAllByTestId('topology-edge')).toHaveLength(0)
  })

  it('fires onTeamClick with the team when a cluster is clicked', async () => {
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} onTeamClick={onTeamClick} />)
    const alpha = screen.getAllByTestId('team-cluster').find(c => c.dataset.team === 'alpha')!
    await userEvent.click(alpha)
    expect(onTeamClick).toHaveBeenCalledWith('alpha')
  })

  it('marks the selected team + node with data-selected', () => {
    render(<TopologyGraph nodes={NODES4} edges={EDGES3} selectedTeam="beta" selectedNodeId="p1" />)
    const beta = screen.getAllByTestId('team-cluster').find(c => c.dataset.team === 'beta')!
    expect(beta).toHaveAttribute('data-selected', 'true')
    const planner = screen.getAllByTestId('topology-node').find(g => g.querySelector('.topology-node__name')?.textContent?.includes('planner'))!
    expect(planner).toHaveAttribute('data-selected', 'true')
  })
})

// ── Unconfigured budget limits (AAASM-5135) ──────────────────────────────────
// A `null` limit means no ceiling is configured. The card used to print
// `$4.1 / $0` and the cluster tooltip `$5 / $0`, asserting a fully-burnt budget
// on data that says nothing at all about the ceiling.
describe('TopologyGraph — unconfigured budget limits', () => {
  const NO_LIMIT: TopologyNode[] = [
    { id: 'u1', name: 'unbudgeted', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 4.1, budgetLimit: null },
  ]

  it('never renders a $0 ceiling on the node card', () => {
    render(<TopologyGraph nodes={NO_LIMIT} edges={[]} />)
    const budget = screen.getByTestId('topology-node-budget')
    expect(budget).toHaveTextContent('$4.1')
    expect(budget.textContent).not.toContain('$0')
    expect(budget).toHaveAttribute('data-truth-state', 'unconfigured')
  })

  it('gives assistive tech a sentence, not a stray dash', () => {
    render(<TopologyGraph nodes={NO_LIMIT} edges={[]} />)
    // SVG text cannot host the span-based TruthfulValue, so the announcement
    // rides on a <title>; without it the `—` is silent to a screen reader.
    const title = screen.getByTestId('topology-node-budget').querySelector('title')
    expect(title?.textContent).toMatch(/Unconfigured/i)
  })

  it('keeps the card at the base size rather than inventing a burn ratio', () => {
    render(<TopologyGraph nodes={NO_LIMIT} edges={[]} />)
    expect(screen.getByTestId('topology-node')).toHaveAttribute('data-size-bucket', 'small')
  })

  it('makes a team total unknown when any member has no ceiling', () => {
    // A sum over a set with a hole is not a sum: totalling only the members
    // that happen to have a limit would understate the team's real budget.
    const mixed: TopologyNode[] = [
      { id: 'm1', name: 'm1', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 3, budgetLimit: 10 },
      { id: 'm2', name: 'm2', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 2, budgetLimit: null },
    ]
    render(<TopologyGraph nodes={mixed} edges={[]} />)
    const bar = screen.getByTestId('team-budget-bar')
    expect(bar).toHaveAttribute('data-truth-state', 'unconfigured')
    expect(bar).not.toHaveAttribute('aria-valuenow')
    // The $10 that *is* configured must not be presented as the team ceiling.
    expect(bar).not.toHaveTextContent('$10')
  })

  it('still totals a team whose members all have ceilings', () => {
    const known: TopologyNode[] = [
      { id: 'k1', name: 'k1', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 3, budgetLimit: 10 },
      { id: 'k2', name: 'k2', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 2, budgetLimit: 10 },
    ]
    render(<TopologyGraph nodes={known} edges={[]} />)
    const bar = screen.getByTestId('team-budget-bar')
    expect(bar).toHaveAttribute('aria-valuenow', '25')
    expect(bar).toHaveTextContent('$5 / $20 · 25%')
  })

  /**
   * AAASM-5185 changed this cluster bar, and it is the only topology surface it
   * changed — `TopologyGraph` renders the shared `TeamBudgetBar`, so moving that
   * component onto `bucketForConfiguredBudget` reached here too. It went
   * `ok` / `aria-valuenow="0"` / `$500 / $0 · 0%` → `danger` / `100` / `100%`.
   *
   * Retained deliberately rather than reverted, and pinned here so it can never
   * change again unobserved: a cluster total of `$0` cannot mean "unconfigured"
   * on this surface, because the sum goes `null` the moment any member lacks a
   * ceiling (see the mixed-members case above). Reaching `0` therefore requires
   * every member to carry an explicitly-configured `$0` — a team that denies
   * every agent in it, which is not a team with no budget.
   *
   * The sibling surfaces still disagree: `selectTeamBudget` and the node-detail
   * panel both read `limit > 0` and report a configured `$0` as "no limit". That
   * inconsistency is recorded as PRODUCT-DECISION-REQUIRED (AAASM-5251), not
   * resolved here.
   */
  it('treats a team total of $0 as a ceiling that denies, not as an absent one', () => {
    const allZero: TopologyNode[] = [
      { id: 'z1', name: 'z1', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 300, budgetLimit: 0 },
      { id: 'z2', name: 'z2', status: 'active', team: 'alpha', owner: 'a', policyCount: 0, budgetSpend: 200, budgetLimit: 0 },
    ]
    render(<TopologyGraph nodes={allZero} edges={[]} />)
    const bar = screen.getByTestId('team-budget-bar')

    // A measurement, not an absence — the distinction AAASM-5135 established.
    expect(bar).not.toHaveAttribute('data-truth-state')
    expect(bar.dataset.thresholdBucket).toBe('danger')
    expect(bar).toHaveAttribute('aria-valuenow', '100')
    expect(bar).toHaveTextContent('$500 / $0 · 100%')
  })
})

// ── Cross-team badge under a team filter (AAASM-5138) ────────────────────────
// The page trims the canvas to edges whose endpoints are both visible, so a
// team filter deleted the team's external relationships from the picture while
// the sidebar went on counting them. The badge is what accounts for them.
describe('TopologyGraph — cross-team badge', () => {
  const ALL_NODES: TopologyNode[] = [
    { id: 'p1', name: 'planner', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, mode: 'enforce' },
    { id: 'w1', name: 'worker', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10, mode: 'enforce' },
    { id: 'x1', name: 'x-caller', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10, mode: 'enforce' },
    { id: 'x2', name: 'x-second', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10, mode: 'enforce' },
  ]
  const ALL_EDGES: TopologyEdge[] = [
    { source: 'p1', target: 'w1', kind: 'delegation' }, // intra-alpha
    { source: 'p1', target: 'x1', kind: 'call' },       // cross-team
    { source: 'p1', target: 'x2', kind: 'call' },       // cross-team
    { source: 'w1', target: 'x1', kind: 'reads' },      // cross-team
  ]
  // What TopologyPage passes once "alpha" is selected.
  const ALPHA_NODES = ALL_NODES.filter(n => n.team === 'alpha')
  const ALPHA_EDGES = ALL_EDGES.filter(e => e.source !== 'x1' && e.target !== 'x1' && e.source !== 'x2' && e.target !== 'x2')

  function renderFiltered() {
    return render(
      <TopologyGraph
        nodes={ALPHA_NODES}
        edges={ALPHA_EDGES}
        allNodes={ALL_NODES}
        allEdges={ALL_EDGES}
        teamFilterActive
      />,
    )
  }

  it('badges each node with the cross-team edges the filter removed', () => {
    renderFiltered()
    const badges = screen.getAllByTestId('topology-node-crossteam')
    // `data-count` is read rather than `textContent`, which in SVG also
    // includes the badge's own <title> child.
    expect(badges.map(b => b.getAttribute('data-count'))).toEqual(['2', '1'])
    expect(badges[0].textContent).toContain('⇆2')
    expect(badges[1].textContent).toContain('⇆1')
  })

  /**
   * The agreement the whole ticket turns on: the sidebar's cross-team counter
   * describes the fleet, the canvas draws a subset — and every crossing the
   * canvas dropped is accounted for by a badge. Nothing vanishes silently.
   */
  it('accounts for every dropped crossing, so count and picture agree', () => {
    renderFiltered()
    const drawnCrossTeam = screen
      .queryAllByTestId('topology-edge')
      .filter(p => p.getAttribute('data-cross-team') === 'true').length
    const badged = screen
      .getAllByTestId('topology-node-crossteam')
      .reduce((total, b) => total + Number(b.getAttribute('data-count')), 0)

    // 3 of the 4 edges cross a boundary; the filtered canvas draws none of them.
    expect(drawnCrossTeam).toBe(0)
    expect(drawnCrossTeam + badged).toBe(3)
  })

  it('shows no badge when the whole fleet is on screen', () => {
    // Unfiltered, every crossing is already drawn — a badge would restate what
    // the operator can see.
    render(<TopologyGraph nodes={ALL_NODES} edges={ALL_EDGES} allNodes={ALL_NODES} allEdges={ALL_EDGES} />)
    expect(screen.queryAllByTestId('topology-node-crossteam')).toHaveLength(0)
  })

  it('mirrors the count onto data-cross-team-count for the filtered nodes', () => {
    renderFiltered()
    const cards = screen.getAllByTestId('topology-node')
    expect(cards[0]).toHaveAttribute('data-cross-team-count', '2')
    expect(cards[1]).toHaveAttribute('data-cross-team-count', '1')
  })

  it('renders the badge on a node carrying no enforcement mode', () => {
    // The count must not depend on whether the mode badge happens to render.
    const modeless = ALPHA_NODES.map(n => ({ ...n, mode: undefined }))
    render(
      <TopologyGraph nodes={modeless} edges={ALPHA_EDGES} allNodes={ALL_NODES} allEdges={ALL_EDGES} teamFilterActive />,
    )
    expect(screen.getAllByTestId('topology-node-crossteam')).toHaveLength(2)
  })

  it('explains the badge to assistive tech', () => {
    renderFiltered()
    const title = screen.getAllByTestId('topology-node-crossteam')[0].querySelector('title')
    // Deliberately not "hidden by the team filter": the cross-team toggle and
    // the edge-kind checkboxes drop edges too, so the badge does not attribute
    // the omission to a cause it cannot know.
    expect(title?.textContent).toMatch(/not drawn on this view/i)
  })
})

// ── The unclaimed cluster is named and selectable (AAASM-5184) ──────────────
//
// AAASM-5140 made this cluster inert because it was keyed by the empty string,
// which `TopologyPage` reads as falsy — the click opened nothing. That was a
// stopgap which deferred the naming decision to this ticket. With a real key
// and a real label the panel opens, so the affordance is restored.
describe('TopologyGraph — cluster for agents with no team', () => {
  const MIXED: TopologyNode[] = [
    { id: 'g1', name: 'governed', status: 'active', team: 'support', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'o1', name: 'teamless', status: 'active', team: UNCLAIMED_TEAM, owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  ]

  const unclaimedCluster = () =>
    screen.getAllByTestId('team-cluster').find(c => c.dataset.team === UNCLAIMED_TEAM)!

  it('labels the unclaimed group instead of leaving it blank', () => {
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={vi.fn()} />)
    const cluster = unclaimedCluster()
    expect(cluster).toHaveAttribute('data-unclaimed', 'true')
    const label = within(cluster).getByTestId('team-cluster-label')
    // The visible name, not the sentinel key and not an empty string.
    expect(label).toHaveTextContent(/unclaimed/i)
    expect(label.textContent).not.toContain(UNCLAIMED_TEAM)
    expect(label.textContent?.trim()).not.toBe('')
  })

  it('makes the unclaimed group selectable now that its panel opens', async () => {
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={onTeamClick} />)
    const cluster = unclaimedCluster()
    expect(cluster).toHaveAttribute('role', 'button')
    expect(cluster).not.toHaveAttribute('data-selectable', 'false')
    await userEvent.click(cluster)
    // The key it reports is the sentinel, which `TopologyPage` holds as a
    // truthy `selectedTeam` — the dead click of AAASM-5140 is gone.
    expect(onTeamClick).toHaveBeenCalledWith(UNCLAIMED_TEAM)
  })

  it.each([['Enter'], [' ']])('opens the unclaimed group from the keyboard with %s', async (key) => {
    // The cluster advertises `role="button"` and a tab stop, so the keyboard
    // path has to work or the affordance is a lie to anyone not using a mouse.
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={onTeamClick} />)
    const cluster = unclaimedCluster()
    expect(cluster).toHaveAttribute('tabindex', '0')
    cluster.focus()
    await userEvent.keyboard(key === ' ' ? '[Space]' : `{${key}}`)
    expect(onTeamClick).toHaveBeenCalledWith(UNCLAIMED_TEAM)
  })

  it('ignores other keys on the cluster', async () => {
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={onTeamClick} />)
    unclaimedCluster().focus()
    await userEvent.keyboard('{Escape}a')
    expect(onTeamClick).not.toHaveBeenCalled()
  })

  it('does not select when the click merely concluded a pan-drag', async () => {
    // Panning the canvas and releasing over a cluster is a pan, not a
    // selection — `consumePanClick` swallows that click.
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={onTeamClick} />)
    const svg = screen.getByTestId('topology-graph')
    const cluster = unclaimedCluster()

    fireEvent.mouseDown(svg, { clientX: 0, clientY: 0 })
    fireEvent.mouseMove(svg, { clientX: 60, clientY: 40 }) // past PAN_CLICK_THRESHOLD
    fireEvent.mouseUp(svg, { clientX: 60, clientY: 40 })
    fireEvent.click(cluster)

    expect(onTeamClick).not.toHaveBeenCalled()

    // The next click, with no drag before it, still selects.
    await userEvent.click(cluster)
    expect(onTeamClick).toHaveBeenCalledWith(UNCLAIMED_TEAM)
  })

  it('leaves real team clusters selectable', async () => {
    const onTeamClick = vi.fn()
    render(<TopologyGraph nodes={MIXED} edges={[]} onTeamClick={onTeamClick} />)
    const support = screen.getAllByTestId('team-cluster').find(c => c.dataset.team === 'support')!
    expect(support).toHaveAttribute('role', 'button')
    await userEvent.click(support)
    expect(onTeamClick).toHaveBeenCalledWith('support')
  })
})

// ── Neighbour focus on node select (AAASM-5137) ──────────────────────────────
// Selecting a node keeps it and its immediate neighbours lit while everything
// unconnected recedes (data-dimmed → CSS opacity 0.2 / 0.07), mirroring the
// `connectedIds` focus treatment in design/v2/hi-fi/topology.jsx:392.
describe('TopologyGraph — neighbour focus on node select', () => {
  const NODES: TopologyNode[] = [
    { id: 'p1', name: 'planner', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'w1', name: 'worker', status: 'active', team: 'alpha', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'x1', name: 'x-caller', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    // Outside p1's neighbourhood — these must dim when p1 is selected.
    { id: 'lone', name: 'lone', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    { id: 'lone2', name: 'lone-two', status: 'active', team: 'beta', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  ]
  const EDGES: TopologyEdge[] = [
    { source: 'p1', target: 'w1', kind: 'delegation' }, // p1 ↔ w1
    { source: 'x1', target: 'p1', kind: 'call' },        // p1 ↔ x1 (target side)
  ]

  const nodeNamed = (name: string) =>
    screen.getAllByTestId('topology-node').find(
      g => g.querySelector('.topology-node__name')?.textContent?.includes(name),
    )!

  it('keeps the selected node and its neighbours undimmed', () => {
    render(<TopologyGraph nodes={NODES} edges={EDGES} selectedNodeId="p1" />)
    expect(nodeNamed('planner')).not.toHaveAttribute('data-dimmed')
    expect(nodeNamed('worker')).not.toHaveAttribute('data-dimmed')
    expect(nodeNamed('x-caller')).not.toHaveAttribute('data-dimmed')
  })

  it('dims a node connected to neither the selection nor its neighbours', () => {
    render(<TopologyGraph nodes={NODES} edges={EDGES} selectedNodeId="p1" />)
    expect(nodeNamed('lone')).toHaveAttribute('data-dimmed', 'true')
  })

  it('dims edges touching neither the selection nor a neighbour', () => {
    // Add an edge whose endpoints are both outside p1's neighbourhood
    // (lone ↔ lone-two). p1's own two edges must stay lit; the outside edge
    // must dim.
    const edges: TopologyEdge[] = [...EDGES, { source: 'lone', target: 'lone2', kind: 'call' }]
    render(<TopologyGraph nodes={NODES} edges={edges} selectedNodeId="p1" />)
    const dimmed = screen
      .getAllByTestId('topology-edge')
      .filter(p => p.getAttribute('data-dimmed') === 'true')
    // Only the lone→lone-two edge is dimmed; the two edges incident to p1 are lit.
    expect(dimmed).toHaveLength(1)
  })

  it('dims nothing when no node is selected', () => {
    render(<TopologyGraph nodes={NODES} edges={EDGES} />)
    for (const g of screen.getAllByTestId('topology-node')) {
      expect(g).not.toHaveAttribute('data-dimmed')
    }
    for (const p of screen.getAllByTestId('topology-edge')) {
      expect(p).not.toHaveAttribute('data-dimmed')
    }
  })

  it('re-lights everything when the selection is cleared', () => {
    const { rerender } = render(<TopologyGraph nodes={NODES} edges={EDGES} selectedNodeId="p1" />)
    expect(nodeNamed('lone')).toHaveAttribute('data-dimmed', 'true')
    rerender(<TopologyGraph nodes={NODES} edges={EDGES} selectedNodeId={null} />)
    expect(nodeNamed('lone')).not.toHaveAttribute('data-dimmed')
  })
})
