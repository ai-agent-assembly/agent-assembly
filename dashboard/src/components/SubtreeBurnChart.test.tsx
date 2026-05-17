import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { SubtreeBurnChart, BurnTooltip } from './SubtreeBurnChart'
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

// AAASM-1055 AC: "Hovering a layer shows: child agent name, period spend, % of
// subtree". Recharts' Tooltip only renders inside ResponsiveContainer on a real
// layout pass, which jsdom does not provide. We exercise `BurnTooltip` directly
// with a synthesised payload — the same component the chart mounts at runtime —
// so the content contract is locked down by tests.
describe('SubtreeBurnChart — tooltip content', () => {
  const childName = new Map<string, string>([
    ['child-1', 'analyst-bot'],
    ['child-2', 'reviewer-bot'],
  ])

  it('formats each child row with name, USD spend, and percent of subtree', () => {
    render(
      <BurnTooltip
        active
        label="2026-05-16"
        childName={childName}
        payload={[
          { dataKey: 'child-1', value: 12.5, color: '#4f9aff' },
          { dataKey: 'child-2', value: 4.75, color: '#ffb84d' },
        ]}
      />,
    )

    const tooltip = screen.getByTestId('subtree-burn-tooltip')
    expect(tooltip).toHaveTextContent('2026-05-16')
    expect(tooltip).toHaveTextContent('analyst-bot')
    expect(tooltip).toHaveTextContent('reviewer-bot')
    // USD formatted via Intl.NumberFormat compact — exact format is implementation
    // detail; assert key parts via substring instead of strict equality.
    expect(tooltip.textContent ?? '').toMatch(/\$12/)
    expect(tooltip.textContent ?? '').toMatch(/\$4/)
    // Percent of subtree: child-1 is 12.50/17.25 = 72%; child-2 is 27/28%.
    expect(tooltip.textContent ?? '').toMatch(/72%/)
    expect(tooltip.textContent ?? '').toMatch(/2[78]%/)
  })

  it('uses the aggregate total Line value when present (does not double-count)', () => {
    // When the chart's aggregate `total` Line is in the payload, the tooltip
    // must use its value for the Total footer and exclude it from per-child rows.
    render(
      <BurnTooltip
        active
        label="2026-05-16"
        childName={childName}
        payload={[
          { dataKey: 'child-1', value: 5, color: '#4f9aff' },
          { dataKey: 'total', value: 5, color: '#000000' },
        ]}
      />,
    )

    const tooltip = screen.getByTestId('subtree-burn-tooltip')
    // Only one per-child row — the `total` entry must be filtered out.
    const rows = tooltip.querySelectorAll('.sbc__tooltip-row')
    expect(rows.length).toBe(1)
    expect(tooltip).toHaveTextContent('Total:')
  })

  it('renders nothing when not active or payload is empty', () => {
    const { container } = render(
      <BurnTooltip active={false} childName={childName} payload={[]} />,
    )
    expect(container.firstChild).toBeNull()
  })
})
