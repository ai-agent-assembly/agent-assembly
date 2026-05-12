import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterBar } from './FilterBar'
import type { FilterParams } from './urlState'
import type { Agent } from '../agents/api'
import type { TeamSummary } from './useTeamsQuery'

const DEFAULT_FILTERS: FilterParams = { range: '7d', agents: [], teams: [] }

const MOCK_AGENTS: Agent[] = [
  { id: 'a1', name: 'Agent One', framework: 'langgraph', active_sessions: [], metadata: {}, policy_violations_count: 0, recent_events: [], recent_traces: [], session_count: 0, status: 'active', tool_names: [], version: '0.0.1' },
  { id: 'a2', name: 'Agent Two', framework: 'crewai', active_sessions: [], metadata: {}, policy_violations_count: 0, recent_events: [], recent_traces: [], session_count: 0, status: 'active', tool_names: [], version: '0.0.1' },
]

const MOCK_TEAMS: TeamSummary[] = [
  { team_id: 'team-alpha', agent_count: 3, root_agent_count: 1 },
  { team_id: 'team-beta', agent_count: 2, root_agent_count: 1 },
]

describe('FilterBar — data-testid attributes', () => {
  it('has data-testid="analytics-filter-bar" on wrapper', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByTestId('analytics-filter-bar')).toBeInTheDocument()
  })

  it('has data-testid="filter-range" on range select', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByTestId('filter-range')).toBeInTheDocument()
  })

  it('has data-testid="filter-agents" on agents select', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByTestId('filter-agents')).toBeInTheDocument()
  })

  it('has data-testid="filter-teams" on teams select', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByTestId('filter-teams')).toBeInTheDocument()
  })
})

describe('FilterBar — range control', () => {
  it('renders the time range label and select', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByLabelText('Time range')).toBeInTheDocument()
  })

  it('renders all four preset range options plus Custom', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByRole('option', { name: 'Last 24 hours' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Last 7 days' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Last 30 days' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Last 90 days' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Custom range' })).toBeInTheDocument()
  })

  it('reflects the current filter range as the selected option', () => {
    render(
      <FilterBar filters={{ ...DEFAULT_FILTERS, range: '30d' }} onFiltersChange={() => {}} />,
    )
    expect(screen.getByTestId<HTMLSelectElement>('filter-range').value).toBe('30d')
  })

  it('calls onFiltersChange with 24h range on select', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={onChange} />)
    await user.selectOptions(screen.getByTestId('filter-range'), '24h')
    expect(onChange).toHaveBeenCalledWith({ range: '24h' })
  })

  it('calls onFiltersChange with updated range on select change', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={onChange} />)
    await user.selectOptions(screen.getByTestId('filter-range'), '90d')
    expect(onChange).toHaveBeenCalledWith({ range: '90d' })
  })

  it('shows date inputs when Custom range is selected', async () => {
    const user = userEvent.setup()
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    await user.selectOptions(screen.getByTestId('filter-range'), 'custom')
    expect(screen.getByLabelText('Range start date')).toBeInTheDocument()
    expect(screen.getByLabelText('Range end date')).toBeInTheDocument()
  })

  it('shows date inputs when current range is a custom date range', () => {
    render(
      <FilterBar
        filters={{ ...DEFAULT_FILTERS, range: '2024-01-01..2024-01-07' }}
        onFiltersChange={() => {}}
      />,
    )
    expect(screen.getByLabelText('Range start date')).toBeInTheDocument()
    expect(screen.getByLabelText('Range end date')).toBeInTheDocument()
  })

  it('calls onFiltersChange with encoded custom range when both dates entered', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={onChange} />)
    await user.selectOptions(screen.getByTestId('filter-range'), 'custom')
    await user.type(screen.getByLabelText('Range start date'), '2024-01-01')
    await user.type(screen.getByLabelText('Range end date'), '2024-01-07')
    expect(onChange).toHaveBeenLastCalledWith({ range: '2024-01-01..2024-01-07' })
  })
})

describe('FilterBar — agents multi-select', () => {
  it('renders agent options populated from the agents prop', () => {
    render(
      <FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} agents={MOCK_AGENTS} />,
    )
    expect(screen.getByRole('option', { name: 'Agent One' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Agent Two' })).toBeInTheDocument()
  })

  it('reflects currently selected agents', () => {
    render(
      <FilterBar
        filters={{ ...DEFAULT_FILTERS, agents: ['a1'] }}
        onFiltersChange={() => {}}
        agents={MOCK_AGENTS}
      />,
    )
    const select = screen.getByTestId<HTMLSelectElement>('filter-agents')
    expect(Array.from(select.selectedOptions).map(o => o.value)).toEqual(['a1'])
  })
})

describe('FilterBar — teams multi-select', () => {
  it('renders team options populated from the teams prop', () => {
    render(
      <FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} teams={MOCK_TEAMS} />,
    )
    expect(screen.getByRole('option', { name: 'team-alpha' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'team-beta' })).toBeInTheDocument()
  })

  it('reflects currently selected teams', () => {
    render(
      <FilterBar
        filters={{ ...DEFAULT_FILTERS, teams: ['team-alpha'] }}
        onFiltersChange={() => {}}
        teams={MOCK_TEAMS}
      />,
    )
    const select = screen.getByTestId<HTMLSelectElement>('filter-teams')
    expect(Array.from(select.selectedOptions).map(o => o.value)).toEqual(['team-alpha'])
  })
})

describe('FilterBar — accessibility', () => {
  it('has an accessible search landmark', () => {
    render(<FilterBar filters={DEFAULT_FILTERS} onFiltersChange={() => {}} />)
    expect(screen.getByRole('search', { name: 'Analytics filters' })).toBeInTheDocument()
  })
})
