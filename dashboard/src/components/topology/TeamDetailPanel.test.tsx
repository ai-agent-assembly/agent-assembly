import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TeamDetailPanel } from './TeamDetailPanel'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'

const NODES: TopologyNode[] = [
  { id: 'root', name: 'orchestrator', status: 'active', team: 'data', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
  { id: 'child', name: 'etl-worker', status: 'suspended', team: 'data', owner: 'a', policyCount: 1, budgetSpend: 2, budgetLimit: 10, flagged: true },
  { id: 'other', name: 'campaign-bot', status: 'active', team: 'growth', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
]
const EDGES: TopologyEdge[] = [
  { source: 'root', target: 'child', kind: 'delegation' },
  { source: 'root', target: 'other', kind: 'call' }, // cross-team data→growth
]

function renderPanel(overrides: Partial<Parameters<typeof TeamDetailPanel>[0]> = {}) {
  const props = { team: 'data', nodes: NODES, edges: EDGES, onClose: vi.fn(), ...overrides }
  render(<TeamDetailPanel {...props} />)
  return props
}

describe('TeamDetailPanel', () => {
  it('renders the team name and agent/root counts', () => {
    renderPanel()
    expect(screen.getByTestId('team-detail-panel')).toHaveTextContent('data')
    // 2 members (root + child), 1 root.
    expect(screen.getByTestId('team-detail-roots')).toHaveTextContent('2 agents · 1 root')
  })

  it('lists only this team members, depth-sorted, flagging flagged agents', () => {
    renderPanel()
    const members = screen.getAllByTestId('team-detail-member')
    expect(members.map((m) => m.dataset.nodeId)).toEqual(['root', 'child'])
    // Root marked, child flagged with ⚑.
    expect(members[0]).toHaveAttribute('data-root', 'true')
    expect(members[1]).toHaveTextContent('⚑ etl-worker')
  })

  it('counts cross-team edges leaving the team', () => {
    renderPanel()
    expect(screen.getByTestId('team-detail-crossteam-count')).toHaveTextContent('1 edge to other teams')
  })

  it('fires onClose when the close button is clicked', async () => {
    const { onClose } = renderPanel()
    await userEvent.click(screen.getByTestId('team-detail-close'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('drills into a member when onSelectNode is provided', async () => {
    const onSelectNode = vi.fn()
    renderPanel({ onSelectNode })
    await userEvent.click(screen.getAllByTestId('team-detail-member')[1].querySelector('button')!)
    expect(onSelectNode).toHaveBeenCalledWith(NODES[1])
  })

  it('shows the multi-root note only when a team has more than one root', () => {
    renderPanel()
    expect(screen.queryByTestId('team-detail-multiroot')).toBeNull()
    // growth has a single member which is a root → still single-root, no note.
    renderPanel({ team: 'growth' })
    expect(screen.queryByTestId('team-detail-multiroot')).toBeNull()
  })
})
