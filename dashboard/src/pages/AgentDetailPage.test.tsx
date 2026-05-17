import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, afterEach, vi } from 'vitest'
import type { UseQueryResult } from '@tanstack/react-query'
import { FleetPage } from './FleetPage'
import { AgentDetailPage } from './AgentDetailPage'
import { ToastProvider } from '../components/ToastProvider'
import * as agentsApi from '../features/agents/api'
import type { Agent, LogEntry } from '../features/agents/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

function LocationProbe({ onChange }: { onChange: (path: string, search: string) => void }) {
  const loc = useLocation()
  onChange(loc.pathname, loc.search)
  return null
}

function renderApp(initialPath: string, onLocation?: (path: string, search: string) => void) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <MemoryRouter initialEntries={[initialPath]}>
          <Routes>
            <Route path="/agents" element={<FleetPage />}>
              <Route path=":id" element={<AgentDetailPage />} />
            </Route>
          </Routes>
          {onLocation && <LocationProbe onChange={onLocation} />}
        </MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

const MOCK_AGENT: Agent = {
  id: 'abc123',
  name: 'alpha-agent',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 10,
  policy_violations_count: 4,
  tool_names: ['web_search'],
  metadata: { owner: 'alice' },
  pid: null,
}

const MOCK_LOG: LogEntry = {
  agent_id: 'abc123',
  event_type: 'PolicyViolation',
  payload: '{}',
  seq: 1,
  session_id: 'session-12345678',
  timestamp: '2026-05-12T00:00:00Z',
}

function mockHappyPath() {
  vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
    mockQuery<Agent[]>({ data: [MOCK_AGENT], isLoading: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
    mockQuery<Agent | undefined>({ data: MOCK_AGENT, isLoading: false, isError: false, refetch: vi.fn() }),
  )
  vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
    mockQuery<LogEntry[]>({ data: [MOCK_LOG], isLoading: false, isError: false }),
  )
  // AAASM-1053: the Capability tab now renders InheritedPermissionsPanel,
  // which calls useAgentCapabilitiesQuery. Mock to a stable empty cascade
  // so the panel hits its no-cascade-contribution empty state.
  vi.spyOn(agentsApi, 'useAgentCapabilitiesQuery').mockReturnValue(
    mockQuery<agentsApi.EffectivePermissions>({
      data: { allow: [], deny: [], sources: [] },
      isLoading: false,
      isError: false,
    }),
  )
}

afterEach(() => { vi.restoreAllMocks() })

describe('AgentDetailPage deep link', () => {
  it('renders the drawer when navigated directly to /agents/:id', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    expect(await screen.findByTestId('drawer-panel')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail')).toBeInTheDocument()
  })

  it('renders the Fleet table underneath the drawer (route is nested)', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    expect(await screen.findByTestId('fleet-page')).toBeInTheDocument()
    expect(screen.getByTestId('drawer-panel')).toBeInTheDocument()
  })

  it('formats the DID using metadata.owner', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    expect(await screen.findByTestId('agent-detail-did')).toHaveTextContent('did:agent:alice:abc123')
  })

  it('falls back to the agent-assembly slug when owner metadata is missing', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [MOCK_AGENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({
        data: { ...MOCK_AGENT, metadata: {} },
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: [MOCK_LOG], isLoading: false, isError: false }),
    )
    renderApp('/agents/abc123')
    expect(await screen.findByTestId('agent-detail-did')).toHaveTextContent('did:agent:agent-assembly:abc123')
  })
})

describe('AgentDetailPage close behavior', () => {
  it('closes back to /agents when the breadcrumb button is clicked', async () => {
    mockHappyPath()
    let lastPath = ''
    renderApp('/agents/abc123', (p) => { lastPath = p })
    fireEvent.click(await screen.findByTestId('agent-detail-close'))
    await waitFor(() => expect(lastPath).toBe('/agents'))
  })

  it('preserves the Fleet filter query string when closing', async () => {
    mockHappyPath()
    let lastSearch = ''
    renderApp('/agents/abc123?q=alpha&status=active', (_, s) => { lastSearch = s })
    fireEvent.click(await screen.findByTestId('agent-detail-close'))
    await waitFor(() => expect(lastSearch).toContain('q=alpha'))
    expect(lastSearch).toContain('status=active')
  })

  it('closes when the scrim is clicked', async () => {
    mockHappyPath()
    let lastPath = ''
    renderApp('/agents/abc123', (p) => { lastPath = p })
    const scrim = await screen.findByTestId('drawer-scrim')
    fireEvent.click(scrim)
    await waitFor(() => expect(lastPath).toBe('/agents'))
  })

  it('closes when Escape is pressed', async () => {
    mockHappyPath()
    let lastPath = ''
    renderApp('/agents/abc123', (p) => { lastPath = p })
    await screen.findByTestId('drawer-panel')
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(lastPath).toBe('/agents'))
  })
})

describe('AgentDetailPage tab navigation', () => {
  it('starts on the Overview tab with posture and recent-events panels', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    expect(await screen.findByTestId('agent-detail-posture')).toBeInTheDocument()
    expect(screen.getByTestId('agent-events')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-tab-overview')).toHaveAttribute('aria-selected', 'true')
  })

  it('switches to the InheritedPermissionsPanel when the Capability tab is selected', async () => {
    // AAASM-1053: Capability tab no longer renders the TabEmpty placeholder;
    // it mounts the live InheritedPermissionsPanel. With mockHappyPath's
    // empty cascade the panel renders its no-cascade-contribution empty
    // state.
    mockHappyPath()
    renderApp('/agents/abc123')
    fireEvent.click(await screen.findByTestId('agent-detail-tab-capability'))
    await waitFor(() => expect(screen.getByTestId('inherited-permissions-empty')).toBeInTheDocument())
    expect(screen.queryByTestId('agent-detail-posture')).not.toBeInTheDocument()
  })

  it('renders the other follow-up tabs each with their empty state', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    for (const id of ['traffic', 'policies', 'lineage', 'config'] as const) {
      fireEvent.click(screen.getByTestId(`agent-detail-tab-${id}`))
      await waitFor(() => expect(screen.getByTestId(`ad-tab-empty-${id}`)).toBeInTheDocument())
    }
  })
})

describe('AgentDetailPage loading and error states', () => {
  it('shows the loading state while the agent query is in flight', () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: undefined, isLoading: true, isError: false }),
    )
    renderApp('/agents/abc123')
    expect(screen.getByTestId('agent-detail-loading')).toBeInTheDocument()
  })

  it('shows an error banner with Retry when the agent query fails', () => {
    const refetch = vi.fn()
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: undefined, isLoading: false, isError: true }),
    )
    renderApp('/agents/abc123')
    expect(screen.getByTestId('agent-detail-error')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })
})

describe('AgentDetailPage drawer head action buttons', () => {
  it('renders the trace + shadow + suspend three-button group for an active agent', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    await screen.findByTestId('agent-detail')
    expect(screen.getByTestId('agent-detail-trace')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-trace')).toHaveTextContent(/trace last call/i)
    expect(screen.getByTestId('agent-detail-shadow')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-shadow')).toHaveTextContent(/shadow mode/i)
    expect(screen.getByTestId('agent-detail-suspend')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-detail-resume')).not.toBeInTheDocument()
  })

  it('swaps suspend for resume when the agent is already suspended (3-button group intact)', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [MOCK_AGENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({
        data: { ...MOCK_AGENT, status: 'suspended' },
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: [MOCK_LOG], isLoading: false, isError: false }),
    )
    renderApp('/agents/abc123')
    await screen.findByTestId('agent-detail')
    expect(screen.getByTestId('agent-detail-trace')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-shadow')).toBeInTheDocument()
    expect(screen.getByTestId('agent-detail-resume')).toBeInTheDocument()
    expect(screen.queryByTestId('agent-detail-suspend')).not.toBeInTheDocument()
  })

  it('trace last call button fires a toast with the agent id', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    fireEvent.click(await screen.findByTestId('agent-detail-trace'))
    expect(await screen.findByText(/Opened trace for abc123/)).toBeInTheDocument()
  })

  it('shadow mode button fires a mock toast', async () => {
    mockHappyPath()
    renderApp('/agents/abc123')
    fireEvent.click(await screen.findByTestId('agent-detail-shadow'))
    expect(await screen.findByText(/Switched abc123 to shadow mode/)).toBeInTheDocument()
  })
})
