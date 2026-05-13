import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { FleetPage } from './FleetPage'
import { ToastProvider } from '../components/ToastProvider'
import * as agentsApi from '../features/agents/api'
import type { Agent } from '../features/agents/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function LocationProbe({ onChange }: { onChange: (search: string) => void }) {
  const loc = useLocation()
  onChange(loc.search)
  return null
}

function renderFleet(initialPath = '/agents', onLocation?: (search: string) => void) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <MemoryRouter initialEntries={[initialPath]}>
          <Routes>
            <Route path="/agents" element={<FleetPage />} />
          </Routes>
          {onLocation && <LocationProbe onChange={onLocation} />}
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

function makeAgent(overrides: Partial<Agent> = {}): Agent {
  return {
    id: 'id-a',
    name: 'alpha',
    framework: 'langgraph',
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: null,
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: {},
    pid: null,
    ...overrides,
  }
}

afterEach(() => { vi.restoreAllMocks() })

describe('FleetPage chrome', () => {
  it('renders the page-head with N of M counter and disabled stub actions', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({
        data: [makeAgent({ id: '1' }), makeAgent({ id: '2', name: 'beta' })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderFleet()
    await waitFor(() => expect(screen.getByTestId('fleet-page-head')).toBeInTheDocument())
    expect(screen.getByTestId('fleet-page-count').textContent).toContain('2 of 2 agents')
    expect(screen.getByTestId('fleet-action-register')).toBeDisabled()
    expect(screen.getByTestId('fleet-action-export')).toBeDisabled()
  })

  it('switches to the Active Sessions empty-state when its tab is selected', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [makeAgent()], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderFleet()
    fireEvent.click(screen.getByTestId('fleet-tab-sessions'))
    await waitFor(() => expect(screen.getByTestId('fleet-sessions-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('agents-table')).not.toBeInTheDocument()
  })
})

describe('FleetPage filter bar', () => {
  it('narrows the agent list with the search input and updates the counter', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({
        data: [makeAgent({ id: '1', name: 'alpha' }), makeAgent({ id: '2', name: 'beta' })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderFleet()
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(2))

    fireEvent.change(screen.getByTestId('fleet-filter-search'), { target: { value: 'beta' } })
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(1))
    expect(screen.getByTestId('fleet-page-count').textContent).toContain('1 of 2 agents')
  })

  it('filters by status when a status chip is selected', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({
        data: [
          makeAgent({ id: '1', status: 'active' }),
          makeAgent({ id: '2', status: 'suspended' }),
        ],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderFleet()
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('fleet-filter-status-suspended'))
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(1))
  })

  it('honours the flagged-only checkbox', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({
        data: [
          makeAgent({ id: '1', policy_violations_count: 0 }),
          makeAgent({ id: '2', policy_violations_count: 200 }),
        ],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderFleet()
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(2))

    fireEvent.click(screen.getByTestId('fleet-filter-flagged'))
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(1))
  })
})

describe('FleetPage URL filter sync', () => {
  it('hydrates filter state from the URL on first render', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({
        data: [
          makeAgent({ id: '1', status: 'active' }),
          makeAgent({ id: '2', status: 'suspended' }),
        ],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderFleet('/agents?status=suspended')
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(1))
    expect(screen.getByTestId('fleet-filter-status-suspended')).toHaveClass('fleet-filters__chip--active')
  })

  it('writes non-default filter changes back to the URL', async () => {
    let lastSearch = ''
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [makeAgent()], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderFleet('/agents', (s) => { lastSearch = s })

    fireEvent.change(screen.getByTestId('fleet-filter-search'), { target: { value: 'beta' } })
    await waitFor(() => expect(lastSearch).toContain('q=beta'))

    fireEvent.change(screen.getByTestId('fleet-filter-search'), { target: { value: '' } })
    await waitFor(() => expect(lastSearch).not.toContain('q='))
  })
})

describe('FleetPage loading and error states', () => {
  it('renders skeleton rows while loading', () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderFleet()
    expect(screen.getAllByTestId('agent-row-skeleton')).toHaveLength(5)
  })

  it('renders an empty-state callout when the agent list is empty', () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderFleet()
    expect(screen.getByTestId('agents-empty')).toBeInTheDocument()
  })

  it('renders the error banner with retry when the query fails', () => {
    const refetch = vi.fn()
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderFleet()
    expect(screen.getByTestId('agents-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })
})
