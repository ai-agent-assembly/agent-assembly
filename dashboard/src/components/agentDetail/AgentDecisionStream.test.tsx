import { render, screen, fireEvent, within } from '@testing-library/react'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { AgentDecisionStream } from './AgentDecisionStream'
import * as agentsApi from '../../features/agents/api'
import type { AgentDecision } from '../../features/agents/api'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function decision(overrides: Partial<AgentDecision>): AgentDecision {
  return {
    timestamp: '2026-07-24T10:20:30Z',
    sessionId: 'ee'.repeat(16),
    seq: 0,
    verb: 'TOOL_CALL',
    resource: 'pg.users',
    decision: 1,
    decisionLabel: 'allow',
    matchedPolicy: null,
    latencyMs: null,
    ...overrides,
  }
}

afterEach(() => vi.restoreAllMocks())

describe('AgentDecisionStream', () => {
  it('shows the loading state while the query is in flight', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    expect(screen.getByTestId('agent-decisions-loading')).toBeInTheDocument()
  })

  it('shows an error state and retries on demand', () => {
    const refetch = vi.fn()
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    expect(screen.getByTestId('agent-decisions-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('renders the empty state when there are no decisions', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    expect(screen.getByTestId('agent-decisions-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-decisions-table')).not.toBeInTheDocument()
  })

  it('renders one row per decision with verdict, resource and policy', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [
          decision({ seq: 1, decision: 2, decisionLabel: 'deny', matchedPolicy: 'P-066', resource: 'gmail.send' }),
          decision({ seq: 0, decision: 1, decisionLabel: 'allow', resource: 'pg.users' }),
        ],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    const rows = screen.getAllByTestId('agent-decision-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText(/deny/)).toBeInTheDocument()
    expect(within(rows[0]).getByText('P-066')).toBeInTheDocument()
    expect(within(rows[0]).getByText('gmail.send')).toBeInTheDocument()
    expect(within(rows[1]).getByText(/allow/)).toBeInTheDocument()
  })

  it('renders an em dash for a null latency and a null matched policy, never a fabricated value', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [decision({ latencyMs: null, matchedPolicy: null })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    const row = screen.getByTestId('agent-decision-row')
    expect(within(row).getByTestId('agent-decision-latency')).toHaveTextContent('—')
    // No fabricated millisecond value.
    expect(within(row).queryByText(/\d+ms/)).not.toBeInTheDocument()
  })

  it('renders a millisecond latency when the audit event recorded one', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [decision({ latencyMs: 42 })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    const row = screen.getByTestId('agent-decision-row')
    expect(within(row).getByTestId('agent-decision-latency')).toHaveTextContent('42ms')
  })

  it('renders an em dash for a null verb and a null resource', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [decision({ verb: null, resource: null })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    const cells = within(screen.getByTestId('agent-decision-row')).getAllByText('—')
    // Both the verb and resource cells fall back to the em dash.
    expect(cells.length).toBeGreaterThanOrEqual(2)
  })

  it('renders an unknown decision label with neutral styling rather than a guessed verdict colour', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [decision({ decision: 0, decisionLabel: 'unspecified' })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    const verdict = within(screen.getByTestId('agent-decision-row')).getByText(/unspecified/)
    expect(verdict).toHaveStyle({ color: 'var(--ink-3)' })
  })

  it('falls back to the raw timestamp when it is not a valid date', () => {
    vi.spyOn(agentsApi, 'useAgentDecisionsQuery').mockReturnValue(
      mockQuery<AgentDecision[]>({
        data: [decision({ timestamp: 'not-a-date' })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    render(<AgentDecisionStream agentId="a1" />)
    expect(within(screen.getByTestId('agent-decision-row')).getByText('not-a-date')).toBeInTheDocument()
  })
})
