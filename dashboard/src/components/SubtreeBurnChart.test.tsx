import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { SubtreeBurnChart } from './SubtreeBurnChart'
import * as agentsApi from '../features/agents/api'
import type { SubtreeBurn } from '../features/agents/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function renderChart(agentId = 'aabbccdd00112233aabbccdd00112233') {
  return render(
    <QueryClientProvider client={makeClient()}>
      <SubtreeBurnChart agentId={agentId} />
    </QueryClientProvider>,
  )
}

let useAgentSubtreeBurnQuery: Mock

beforeEach(() => {
  useAgentSubtreeBurnQuery = vi.spyOn(agentsApi, 'useAgentSubtreeBurnQuery') as unknown as Mock
})

describe('SubtreeBurnChart — loading and error states', () => {
  it('renders loading state while query is pending', () => {
    useAgentSubtreeBurnQuery.mockReturnValue(mockQuery<SubtreeBurn>({ isLoading: true }))
    renderChart()
    expect(screen.getByTestId('subtree-burn-loading')).toBeInTheDocument()
  })

  it('renders error state when query fails', () => {
    useAgentSubtreeBurnQuery.mockReturnValue(
      mockQuery<SubtreeBurn>({
        isLoading: false,
        isError: true,
        error: new Error('boom'),
        refetch: vi.fn(),
      }),
    )
    renderChart()
    expect(screen.getByTestId('subtree-burn-error')).toBeInTheDocument()
  })
})

describe('SubtreeBurnChart — empty data', () => {
  it('renders empty state when the server returns zero points', () => {
    useAgentSubtreeBurnQuery.mockReturnValue(
      mockQuery<SubtreeBurn>({
        isLoading: false,
        data: { agent_id: 'a', period: '7d', points: [] },
      }),
    )
    renderChart()
    expect(screen.getByTestId('subtree-burn-empty')).toBeInTheDocument()
  })
})

describe('SubtreeBurnChart — populated', () => {
  const data: SubtreeBurn = {
    agent_id: 'aabbccdd00112233aabbccdd00112233',
    period: '7d',
    points: [
      {
        date: '2026-05-16',
        per_child: [
          { child_agent_id: 'child-1', child_name: 'analyst-bot', spent_usd: '12.50' },
          { child_agent_id: 'child-2', child_name: 'reviewer-bot', spent_usd: '4.75' },
        ],
        total_usd: '17.25',
      },
    ],
  }

  beforeEach(() => {
    useAgentSubtreeBurnQuery.mockReturnValue(mockQuery<SubtreeBurn>({ isLoading: false, data }))
  })

  it('renders the chart container and the period toggle', () => {
    renderChart()
    expect(screen.getByTestId('subtree-burn-chart')).toBeInTheDocument()
    expect(screen.getByTestId('subtree-burn-period-7d')).toBeInTheDocument()
    expect(screen.getByTestId('subtree-burn-period-30d')).toBeInTheDocument()
  })

  it('shows the 7d toggle pressed by default', () => {
    renderChart()
    expect(screen.getByTestId('subtree-burn-period-7d')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('subtree-burn-period-30d')).toHaveAttribute('aria-pressed', 'false')
  })
})
