import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentPoliciesTab } from './AgentPoliciesTab'
import * as policiesApi from '../../features/capability/useAgentPolicies'
import type { Policy } from '../../features/capability/types'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function renderTab() {
  return render(
    <MemoryRouter>
      <AgentPoliciesTab agentId="research-bot-04" agentName="research-bot-04" />
    </MemoryRouter>,
  )
}

const POLICIES: Policy[] = [
  { id: 'P-001', name: 'global default-deny', version: '1', scope: 'global', status: 'active', hits24h: 4210, affects: ['research-bot-04'], rules: [] },
  { id: 'P-066', name: 'narrow research writes', version: '3', scope: 'tag:research', status: 'proposed', hits24h: 12, affects: ['research-bot-04'], rules: [] },
]

afterEach(() => vi.restoreAllMocks())

describe('AgentPoliciesTab', () => {
  it('shows the loading state while the query is in flight', () => {
    vi.spyOn(policiesApi, 'useAgentPoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderTab()
    expect(screen.getByTestId('agent-policies-loading')).toBeInTheDocument()
  })

  it('shows an error state and retries on demand', () => {
    const refetch = vi.fn()
    vi.spyOn(policiesApi, 'useAgentPoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderTab()
    expect(screen.getByTestId('agent-policies-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('renders the empty state when no policy targets the agent', () => {
    vi.spyOn(policiesApi, 'useAgentPoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderTab()
    expect(screen.getByTestId('agent-policies-empty')).toBeInTheDocument()
  })

  it('renders one row per affecting policy with id, scope, hits and an open link', () => {
    vi.spyOn(policiesApi, 'useAgentPoliciesQuery').mockReturnValue(
      mockQuery<Policy[]>({ data: POLICIES, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderTab()
    expect(screen.getByTestId('policy-row-P-001')).toHaveTextContent('global default-deny')
    expect(screen.getByTestId('policy-row-P-001')).toHaveTextContent('4,210')
    expect(screen.getByTestId('policy-row-P-066')).toHaveTextContent('tag:research')
    expect(screen.getByTestId('policy-open-P-066')).toHaveAttribute('href', '/policies?policy=P-066')
  })
})
