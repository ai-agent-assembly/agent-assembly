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
})
