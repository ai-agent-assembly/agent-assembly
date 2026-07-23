import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TopologyGraph } from './TopologyGraph'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'

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
  })
})
