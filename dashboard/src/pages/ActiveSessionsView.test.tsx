import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { ActiveSessionsView } from './ActiveSessionsView'
import * as agentsApi from '../features/agents/api'
import type { FleetActiveSession } from '../features/agents/api'

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function LocationProbe({ onChange }: { onChange: (path: string) => void }) {
  const loc = useLocation()
  onChange(loc.pathname)
  return null
}

function makeSession(overrides: Partial<FleetActiveSession> = {}): FleetActiveSession {
  return {
    agent_id: 'aa'.repeat(16),
    agent_name: 'research-bot',
    team_id: 'growth',
    session_id: 'sess-9a4f',
    started_at: new Date(Date.now() - 90_000).toISOString(),
    status: 'running',
    ...overrides,
  }
}

function renderView(onLocation?: (path: string) => void) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={['/agents']}>
        <Routes>
          <Route path="/agents" element={<ActiveSessionsView />} />
          <Route path="/agents/:id" element={<div data-testid="agent-detail" />} />
        </Routes>
        {onLocation && <LocationProbe onChange={onLocation} />}
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => { vi.restoreAllMocks() })

describe('ActiveSessionsView', () => {
  it('renders one row per session with agent, status, and elapsed', () => {
    vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
      mockQuery<FleetActiveSession[]>({
        data: [makeSession(), makeSession({ session_id: 'sess-8b12', agent_name: 'analytics-runner', team_id: null })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderView()

    expect(screen.getAllByTestId('session-row')).toHaveLength(2)
    expect(screen.getByText('sess-9a4f')).toBeInTheDocument()
    expect(screen.getByText('research-bot')).toBeInTheDocument()
    expect(screen.getByText('growth')).toBeInTheDocument()
    expect(screen.getAllByTestId('fleet-status')).toHaveLength(2)
  })

  it('navigates to the agent detail route when a session row is clicked', () => {
    let path = ''
    vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
      mockQuery<FleetActiveSession[]>({
        data: [makeSession({ agent_id: 'bb'.repeat(16) })],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderView((p) => { path = p })

    fireEvent.click(screen.getByTestId('session-row'))
    expect(path).toBe(`/agents/${'bb'.repeat(16)}`)
  })

  it('shows the empty state when there are no sessions', () => {
    vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
      mockQuery<FleetActiveSession[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderView()
    expect(screen.getByTestId('sessions-empty')).toBeInTheDocument()
    expect(screen.queryByTestId('sessions-table')).not.toBeInTheDocument()
  })

  it('renders skeleton rows while loading', () => {
    vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
      mockQuery<FleetActiveSession[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderView()
    expect(screen.getAllByTestId('session-row-skeleton').length).toBeGreaterThan(0)
  })

  it('shows an error state with a retry that refetches', () => {
    const refetch = vi.fn()
    vi.spyOn(agentsApi, 'useActiveSessionsQuery').mockReturnValue(
      mockQuery<FleetActiveSession[]>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderView()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(refetch).toHaveBeenCalledOnce()
  })
})
