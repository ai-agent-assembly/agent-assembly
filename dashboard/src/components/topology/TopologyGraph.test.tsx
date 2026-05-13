import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TopologyGraph } from './TopologyGraph'
import type { TopologyNode } from '../../features/topology/types'

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
    // The handler should not even attach — clicks just no-op.
    await userEvent.click(screen.getByTestId('topology-node'))
    // No assertion target — absence of errors is the contract.
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
      const teams = clusters.map(c => c.getAttribute('data-team')).sort()
      expect(teams).toEqual(['analytics', 'support'])
    })

    it('renders one TeamBudgetBar per cluster with aggregated spend/limit', () => {
      render(<TopologyGraph nodes={TWO_TEAMS} edges={[]} />)
      const bars = screen.getAllByTestId('team-budget-bar')
      expect(bars).toHaveLength(2)

      const support = bars.find(b => b.getAttribute('data-team') === 'support')!
      const analytics = bars.find(b => b.getAttribute('data-team') === 'analytics')!

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
})
