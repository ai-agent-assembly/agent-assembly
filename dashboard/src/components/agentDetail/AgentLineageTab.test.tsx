import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentLineageTab } from './AgentLineageTab'
import * as topologyApi from '../../features/topology/api'
import type { AgentLineage } from '../../features/topology/api'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const CHAIN: AgentLineage = {
  agent_id: 'agent-c',
  ancestor_count: 3,
  ancestors: [
    { id: 'agent-a', name: 'orchestrator', depth: 0, team_id: 'platform', delegation_reason: 'spawn worker' },
    { id: 'agent-b', name: 'router', depth: 1, delegation_reason: 'delegate task' },
    { id: 'agent-c', name: 'research-bot', depth: 2, team_id: 'research' },
  ],
}

afterEach(() => vi.restoreAllMocks())

describe('AgentLineageTab', () => {
  it('shows the loading state while the lineage query is in flight', () => {
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockQuery<AgentLineage>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    render(<AgentLineageTab agentId="agent-c" />)
    expect(screen.getByTestId('agent-lineage-loading')).toBeInTheDocument()
  })

  it('shows an error state and retries on demand', () => {
    const refetch = vi.fn()
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockQuery<AgentLineage>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    render(<AgentLineageTab agentId="agent-c" />)
    expect(screen.getByTestId('agent-lineage-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('renders a root-only callout when the chain has a single node', () => {
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockQuery<AgentLineage>({
        data: { agent_id: 'agent-a', ancestor_count: 1, ancestors: [{ id: 'agent-a', name: 'root-bot', depth: 0 }] },
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentLineageTab agentId="agent-a" />)
    expect(screen.getByTestId('agent-lineage-root-only')).toBeInTheDocument()
  })

  it('renders the delegation chain root → current with the current node marked', () => {
    vi.spyOn(topologyApi, 'useAgentLineageQuery').mockReturnValue(
      mockQuery<AgentLineage>({ data: CHAIN, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    render(<AgentLineageTab agentId="agent-c" />)
    expect(screen.getByTestId('agent-lineage-tab')).toBeInTheDocument()
    expect(screen.getByTestId('lineage-node-agent-a')).toHaveTextContent('root')
    expect(screen.getByTestId('lineage-node-agent-c')).toHaveTextContent('← current')
    // Delegation reason from the prior node surfaces on the connector.
    expect(screen.getByText(/delegate task · depth 2/)).toBeInTheDocument()
  })
})
