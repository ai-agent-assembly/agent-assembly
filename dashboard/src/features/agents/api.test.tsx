import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { vi } from 'vitest'
import { AgentsPage } from '../../pages/AgentsPage'
import { AgentDetailPage } from '../../pages/AgentDetailPage'
import * as agentsApi from './api'
import type { Agent, LogEntry } from './api'
import type { UseQueryResult } from '@tanstack/react-query'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function Wrapper({ children, path = '/', initialPath = '/' }: { children: React.ReactNode; path?: string; initialPath?: string }) {
  return (
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path={path} element={children} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

function mockQuery<T>(partial: Partial<UseQueryResult<T, Error>>): UseQueryResult<T, Error> {
  return partial as unknown as UseQueryResult<T, Error>
}

const MOCK_AGENT: Agent = {
  id: 'abc123',
  name: 'test-agent',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [{ event_type: 'violation', summary: 'limit exceeded', timestamp: '2026-05-12T00:00:00Z' }],
  recent_traces: [],
  active_sessions: [],
  session_count: 3,
  policy_violations_count: 1,
  tool_names: ['web_search', 'code_exec'],
  metadata: {},
  pid: null,
}

const MOCK_LOG: LogEntry = {
  agent_id: 'abc123',
  event_type: 'PolicyViolation',
  payload: '{}',
  seq: 1,
  session_id: 'session-001',
  timestamp: '2026-05-12T00:00:00Z',
}

describe('AgentsPage', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('renders skeleton rows while loading', () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    render(<AgentsPage />, { wrapper: ({ children }) => <Wrapper path="/">{children}</Wrapper> })
    expect(screen.getAllByTestId('agent-row-skeleton')).toHaveLength(5)
  })

  it('renders rows for each agent', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [MOCK_AGENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    render(<AgentsPage />, { wrapper: ({ children }) => <Wrapper path="/">{children}</Wrapper> })
    await waitFor(() => expect(screen.getAllByTestId('agent-row')).toHaveLength(1))
    expect(screen.getByText('test-agent')).toBeInTheDocument()
    expect(screen.getByText('langgraph')).toBeInTheDocument()
    expect(screen.getByText('active')).toBeInTheDocument()
  })

  it('shows empty state when no agents', async () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    render(<AgentsPage />, { wrapper: ({ children }) => <Wrapper path="/">{children}</Wrapper> })
    await waitFor(() => expect(screen.getByTestId('agents-empty')).toBeInTheDocument())
  })

  it('shows error banner with retry button on failure', () => {
    vi.spyOn(agentsApi, 'useAgentsQuery').mockReturnValue(
      mockQuery<Agent[]>({ data: undefined, isLoading: false, isError: true, refetch: vi.fn() }),
    )
    render(<AgentsPage />, { wrapper: ({ children }) => <Wrapper path="/">{children}</Wrapper> })
    expect(screen.getByTestId('agents-error')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })
})

describe('AgentDetailPage', () => {
  afterEach(() => { vi.restoreAllMocks() })

  it('renders identity profile fields', async () => {
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({ data: MOCK_AGENT, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: [MOCK_LOG], isLoading: false, isError: false }),
    )

    render(
      <Wrapper path="/agents/:id" initialPath="/agents/abc123">
        <AgentDetailPage />
      </Wrapper>,
    )

    await waitFor(() => expect(screen.getByTestId('agent-detail')).toBeInTheDocument())
    expect(screen.getByText('test-agent')).toBeInTheDocument()
    expect(screen.getByText('langgraph')).toBeInTheDocument()
    expect(screen.getByText('enforced')).toBeInTheDocument()
    expect(screen.getAllByTestId('event-row')).toHaveLength(1)
  })

  it('shows loading state', () => {
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockQuery<Agent | undefined>({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    vi.spyOn(agentsApi, 'useAgentEventsQuery').mockReturnValue(
      mockQuery<LogEntry[]>({ data: undefined, isLoading: true, isError: false }),
    )

    render(
      <Wrapper path="/agents/:id" initialPath="/agents/abc123">
        <AgentDetailPage />
      </Wrapper>,
    )
    expect(screen.getByTestId('agent-detail-loading')).toBeInTheDocument()
  })
})
