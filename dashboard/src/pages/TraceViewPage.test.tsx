import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { TraceViewPage } from './TraceViewPage'
import * as traceApi from '../features/trace/api'
import type { TraceEvent } from '../features/trace/types'

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

function mockQuery(partial: Partial<UseQueryResult<TraceEvent[], Error>>): UseQueryResult<TraceEvent[], Error> {
  return partial as unknown as UseQueryResult<TraceEvent[], Error>
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
  afterEach(() => { vi.restoreAllMocks() })

  it('renders the agent id and session id from URL params in the header', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const heading = screen.getByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('agent-001')
    expect(heading).toHaveTextContent('session-abc')
  })

  it('exposes a back link to the agent detail page', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const link = screen.getByRole('link', { name: /Back to agent/i })
    expect(link).toHaveAttribute('href', '/agents/agent-001')
  })

  it('renders skeleton rows while loading', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: true, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-loading')).toBeInTheDocument()
    expect(screen.getAllByTestId('trace-row-skeleton')).toHaveLength(4)
  })

  it('shows error banner with Retry button on failure and calls refetch on click', async () => {
    const refetch = vi.fn()
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-error')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('shows empty state when no events', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-empty')).toBeInTheDocument()
  })

  it('mounts the timeline placeholder slot with event count when ready', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const placeholder = screen.getByTestId('trace-timeline-placeholder')
    expect(placeholder).toBeInTheDocument()
    expect(placeholder).toHaveTextContent('1 event')
  })
})
