import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NodeDetailPanel } from './NodeDetailPanel'
import * as topologyApi from '../../features/topology/api'
import * as agentMutations from '../../features/agents/mutations'
import type { AgentLineage, RecentEvent } from '../../features/topology/api'
import type { TopologyEdge, TopologyNode } from '../../features/topology/types'

const NODE: TopologyNode = {
  id: 'agent-001',
  name: 'support-agent',
  status: 'active',
  team: 'support',
  owner: 'alice',
  policyCount: 3,
  budgetSpend: 4.1,
  budgetLimit: 10,
  framework: 'langgraph',
  latestSessionId: 'sess-7',
}

const RECENT: RecentEvent[] = [
  { id: 'e1', timestamp: '2026-05-13T10:00:00Z', type: 'tool_call', message: 'query_db users' },
  { id: 'e2', timestamp: '2026-05-13T10:01:00Z', type: 'policy_violation', message: 'refund > $100' },
]

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderPanel(
  node: TopologyNode | null,
  onClose = vi.fn(),
  onViewTrace = vi.fn(),
) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <NodeDetailPanel node={node} onClose={onClose} onViewTrace={onViewTrace} />
    </QueryClientProvider>,
  )
}

function mockRecent(partial: Partial<UseQueryResult<readonly RecentEvent[], Error>>): UseQueryResult<readonly RecentEvent[], Error> {
  return partial as unknown as UseQueryResult<readonly RecentEvent[], Error>
}

describe('NodeDetailPanel', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('returns null when node is null', () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    const { container } = renderPanel(null)
    expect(container.firstChild).toBeNull()
  })

  it('renders agent name, status badge, identity fields, policy count, budget summary', () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: RECENT, isLoading: false, isError: false }),
    )
    renderPanel(NODE)

    expect(screen.getByTestId('node-detail-panel')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2 })).toHaveTextContent('support-agent')
    expect(screen.getByTestId('node-detail-status')).toHaveTextContent('active')
    expect(screen.getByTestId('node-detail-identity')).toHaveTextContent('agent-001')
    expect(screen.getByTestId('node-detail-identity')).toHaveTextContent('alice')
    expect(screen.getByTestId('node-detail-identity')).toHaveTextContent('support')
    expect(screen.getByTestId('node-detail-identity')).toHaveTextContent('langgraph')
    expect(screen.getByTestId('node-detail-policy-count')).toHaveTextContent('3 policies')
    expect(screen.getByTestId('node-detail-budget')).toHaveTextContent('$4.10 / $10.00')
    expect(screen.getByTestId('node-detail-progress')).toHaveAttribute('aria-valuenow', '41')
  })

  it('renders recent events (top 5) with type and message', () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: RECENT, isLoading: false, isError: false }),
    )
    renderPanel(NODE)
    const events = screen.getAllByTestId('node-detail-event')
    expect(events).toHaveLength(2)
    expect(events[0]).toHaveTextContent('tool_call')
    expect(events[1]).toHaveTextContent('refund > $100')
  })

  it('caps the recent events list at 5 entries', () => {
    const many = Array.from({ length: 8 }, (_, i): RecentEvent => ({
      id: `e${i}`,
      timestamp: `2026-05-13T10:0${i}:00Z`,
      type: 'tool_call',
      message: `evt ${i}`,
    }))
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: many, isLoading: false, isError: false }),
    )
    renderPanel(NODE)
    expect(screen.getAllByTestId('node-detail-event')).toHaveLength(5)
  })

  it('shows the empty-recent hint when there are no events', () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    renderPanel(NODE)
    expect(screen.getByText('No recent activity.')).toBeInTheDocument()
  })

  it('View trace button fires onViewTrace with the node id and latest session id', async () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    const onViewTrace = vi.fn()
    renderPanel(NODE, vi.fn(), onViewTrace)

    await userEvent.click(screen.getByTestId('node-detail-view-trace'))
    expect(onViewTrace).toHaveBeenCalledWith('agent-001', 'sess-7')
  })

  it('disables View trace and shows a tooltip when latestSessionId is missing', async () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    const onViewTrace = vi.fn()
    const nodeWithoutSession: TopologyNode = { ...NODE, latestSessionId: undefined }
    renderPanel(nodeWithoutSession, vi.fn(), onViewTrace)

    const btn = screen.getByTestId('node-detail-view-trace') as HTMLButtonElement
    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute(
      'title',
      'No recent session for this agent yet — run a trace to enable.',
    )

    await userEvent.click(btn)
    expect(onViewTrace).not.toHaveBeenCalled()
  })

  it('Close button + Esc key both fire onClose', async () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    const onClose = vi.fn()
    renderPanel(NODE, onClose)

    await userEvent.click(screen.getByTestId('node-detail-close'))
    expect(onClose).toHaveBeenCalledTimes(1)

    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(2)
  })

  it('outside-click fires onClose', async () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    const onClose = vi.fn()
    render(
      <QueryClientProvider client={makeClient()}>
        <div>
          <button data-testid="outside-target">outside</button>
          <NodeDetailPanel node={NODE} onClose={onClose} onViewTrace={vi.fn()} />
        </div>
      </QueryClientProvider>,
    )
    await userEvent.click(screen.getByTestId('outside-target'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders the governance stub buttons (Apply policy / Shadow / Suspend)', () => {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
    renderPanel(NODE)
    expect(screen.getByTestId('node-detail-apply-policy')).toBeInTheDocument()
    expect(screen.getByTestId('node-detail-shadow-mode')).toBeInTheDocument()
    expect(screen.getByTestId('node-detail-suspend')).toBeInTheDocument()
  })
})

// ── Lineage / cross-team / suspend-resume (AAASM-5071) ───────────────────────
describe('NodeDetailPanel — lineage, cross-team, suspend/resume', () => {
  afterEach(() => vi.restoreAllMocks())

  function mockLineage(partial: Partial<UseQueryResult<AgentLineage, Error>>): UseQueryResult<AgentLineage, Error> {
    return partial as unknown as UseQueryResult<AgentLineage, Error>
  }

  function stubBaseQueries() {
    vi.spyOn(topologyApi, 'useTopologyNodeRecentEvents').mockReturnValue(
      mockRecent({ data: [], isLoading: false, isError: false }),
    )
  }

  function renderWith(node: TopologyNode, extra: Partial<Parameters<typeof NodeDetailPanel>[0]> = {}) {
    return render(
      <QueryClientProvider client={makeClient()}>
        <NodeDetailPanel node={node} onClose={vi.fn()} onViewTrace={vi.fn()} {...extra} />
      </QueryClientProvider>,
    )
  }

  it('renders the delegation lineage chain from the lineage query', () => {
    stubBaseQueries()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockLineage({
        data: {
          agent_id: 'agent-001',
          ancestor_count: 2,
          ancestors: [
            { id: 'root-1', name: 'orchestrator', depth: 0 },
            { id: 'agent-001', name: 'support-agent', depth: 1 },
          ],
        },
        isLoading: false,
        isError: false,
      }),
    )
    renderWith(NODE)
    const steps = screen.getAllByTestId('node-detail-lineage-step')
    expect(steps).toHaveLength(2)
    expect(steps[0]).toHaveTextContent('orchestrator')
    expect(steps[1]).toHaveTextContent('support-agent')
    expect(steps[1]).toHaveTextContent('← here')
  })

  it('shows the root-only lineage hint for a single-node chain', () => {
    stubBaseQueries()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockLineage({
        data: { agent_id: 'agent-001', ancestor_count: 1, ancestors: [{ id: 'agent-001', name: 'support-agent', depth: 0 }] },
        isLoading: false,
        isError: false,
      }),
    )
    renderWith(NODE)
    expect(screen.getByTestId('node-detail-lineage-root')).toBeInTheDocument()
    expect(screen.queryByTestId('node-detail-lineage-chain')).toBeNull()
  })

  it('lists cross-team edges to peers on other teams', () => {
    stubBaseQueries()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(mockLineage({ data: undefined, isLoading: false, isError: false }))
    const nodes: TopologyNode[] = [
      NODE,
      { id: 'peer-x', name: 'x-caller', status: 'active', team: 'growth', owner: 'b', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
      { id: 'peer-same', name: 'same-team', status: 'active', team: 'support', owner: 'a', policyCount: 1, budgetSpend: 1, budgetLimit: 10 },
    ]
    const edges: TopologyEdge[] = [
      { source: 'agent-001', target: 'peer-x', kind: 'call' }, // cross-team
      { source: 'agent-001', target: 'peer-same', kind: 'delegation' }, // same team — excluded
    ]
    renderWith(NODE, { nodes, edges })
    const rows = screen.getAllByTestId('node-detail-crossteam-edge')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toHaveTextContent('x-caller')
    expect(rows[0]).toHaveTextContent('(growth)')
  })

  it('opens the reason dialog and suspends an active agent', async () => {
    stubBaseQueries()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(mockLineage({ data: undefined, isLoading: false, isError: false }))
    const suspend = vi.fn((_v, opts?: { onSuccess?: () => void }) => opts?.onSuccess?.())
    vi.spyOn(agentMutations, 'useSuspendAgent').mockReturnValue(
      { mutate: suspend, isPending: false, isError: false } as unknown as ReturnType<typeof agentMutations.useSuspendAgent>,
    )
    const onAgentMutated = vi.fn()
    renderWith(NODE, { onAgentMutated })

    await userEvent.click(screen.getByTestId('node-detail-suspend'))
    expect(screen.getByTestId('suspend-dialog')).toBeInTheDocument()
    await userEvent.type(screen.getByTestId('suspend-dialog-input'), 'over budget')
    await userEvent.click(screen.getByTestId('suspend-dialog-confirm'))

    expect(suspend).toHaveBeenCalledWith(
      { id: 'agent-001', reason: 'over budget' },
      expect.objectContaining({ onSuccess: expect.any(Function) }),
    )
    expect(onAgentMutated).toHaveBeenCalledTimes(1)
  })

  it('resumes a suspended agent without a reason dialog', async () => {
    stubBaseQueries()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(mockLineage({ data: undefined, isLoading: false, isError: false }))
    const resume = vi.fn((_v, opts?: { onSuccess?: () => void }) => opts?.onSuccess?.())
    vi.spyOn(agentMutations, 'useResumeAgent').mockReturnValue(
      { mutate: resume, isPending: false, isError: false } as unknown as ReturnType<typeof agentMutations.useResumeAgent>,
    )
    const onAgentMutated = vi.fn()
    const suspendedNode: TopologyNode = { ...NODE, status: 'suspended' }
    renderWith(suspendedNode, { onAgentMutated })

    const btn = screen.getByTestId('node-detail-suspend')
    expect(btn).toHaveTextContent('Resume agent')
    await userEvent.click(btn)
    expect(resume).toHaveBeenCalledWith({ id: 'agent-001' }, expect.objectContaining({ onSuccess: expect.any(Function) }))
    expect(screen.queryByTestId('suspend-dialog')).toBeNull()
    expect(onAgentMutated).toHaveBeenCalledTimes(1)
  })
})
