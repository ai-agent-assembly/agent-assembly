import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TraceViewPage } from './TraceViewPage'
import * as traceApi from '../features/trace/api'
import * as agentsApi from '../features/agents/api'
import type { TraceEvent } from '../features/trace/types'
import type { Agent } from '../features/agents/api'

function makeClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function renderAt(path: string) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/agents/:id/trace/:sessionId" element={<TraceViewPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function mockTraceQuery(partial: Partial<UseQueryResult<TraceEvent[], Error>>): UseQueryResult<TraceEvent[], Error> {
  return partial as unknown as UseQueryResult<TraceEvent[], Error>
}

function mockAgentQuery(partial: Partial<UseQueryResult<Agent | undefined, Error>>): UseQueryResult<Agent | undefined, Error> {
  return partial as unknown as UseQueryResult<Agent | undefined, Error>
}

const MOCK_AGENT: Agent = {
  id: 'agent-001',
  name: 'support-agent',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 0,
  policy_violations_count: 0,
  tool_names: [],
  metadata: {},
  pid: null,
}

const MOCK_EVENT: TraceEvent = {
  id: 'evt-1',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'llm_call',
  agent: 'support-agent',
  durationMs: 834,
  payloadPreview: 'GPT-4o · query user #4521 billing',
  payload: {},
  severity: 'info',
}

describe('TraceViewPage', () => {
  beforeEach(() => {
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockAgentQuery({ data: MOCK_AGENT, isLoading: false, isError: false }),
    )
  })

  afterEach(() => { vi.restoreAllMocks() })

  it('renders the agent name and session id from URL params in the header', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('support-agent')
    expect(heading).toHaveTextContent('session-abc')
    expect(screen.getByTestId('trace-agent-label')).toHaveTextContent('support-agent')
  })

  it('falls back to agent id in the header while the agent query has no data', () => {
    vi.spyOn(agentsApi, 'useAgentQuery').mockReturnValue(
      mockAgentQuery({ data: undefined, isLoading: true, isError: false }),
    )
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-agent-label')).toHaveTextContent('agent-001')
  })

  it('exposes a back link to the agent detail page', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const link = screen.getByRole('link', { name: /Back to agent/i })
    expect(link).toHaveAttribute('href', '/agents/agent-001')
  })

  it('renders skeleton rows while loading', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-loading')).toBeInTheDocument()
    expect(screen.getAllByTestId('trace-row-skeleton')).toHaveLength(4)
  })

  it('shows error banner with Retry button on failure and calls refetch on click', async () => {
    const refetch = vi.fn()
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-error')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('shows empty state when no events', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-empty')).toBeInTheDocument()
  })

  it('mounts the timeline placeholder slot with event count when ready', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const placeholder = screen.getByTestId('trace-timeline-placeholder')
    expect(placeholder).toBeInTheDocument()
    expect(placeholder).toHaveTextContent('1 event')
  })
})
