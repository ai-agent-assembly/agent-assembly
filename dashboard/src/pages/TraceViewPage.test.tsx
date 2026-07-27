import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { UseQueryResult } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TraceViewPage } from './TraceViewPage'
import * as traceApi from '../features/trace/api'
import * as agentsApi from '../features/agents/api'
import * as traceExport from '../features/trace/export'
import { traceExportSchema } from '../features/trace/exportSchema'
import { absent, known } from '../lib/truthfulness'
import type { TraceEvent, TraceSeverity } from '../features/trace/types'
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

const NOT_ON_TRACE_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

/**
 * Shaped exactly as `mapSpanToEvent` builds an event from a real `TraceSpan`:
 * the five fields the span schema cannot carry are absences, and the duration
 * of an audit-reconstructed span was never measured. Tests that need a severity
 * have to say so explicitly via {@link withSeverity}.
 */
const MOCK_EVENT: TraceEvent = {
  id: 'evt-1',
  timestamp: '2026-04-23T14:23:01Z',
  type: 'ToolCallIntercepted',
  agent: 'support-agent',
  parentSpanId: null,
  durationMs: absent<number>(
    'unknown',
    'This span recorded no end time, so its duration was never measured',
  ),
  decision: known('allow'),
  payloadPreview: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
  payload: absent<unknown>('not-supported', NOT_ON_TRACE_SPAN),
  severity: absent<TraceSeverity>('not-supported', NOT_ON_TRACE_SPAN),
  redactedFields: absent<readonly string[]>('not-supported', NOT_ON_TRACE_SPAN),
  violationReason: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
}

/** An event carrying a severity — the only shape the filter can act on. */
function withSeverity(id: string, severity: TraceSeverity): TraceEvent {
  return { ...MOCK_EVENT, id, severity: known(severity) }
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

  it('queries the trace by session id alone (the agent is an output of the call)', () => {
    const useTraceQuery = vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(useTraceQuery).toHaveBeenCalledWith('session-abc')
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

  it('renders the unavailable status state with a Retry button on failure and calls refetch on click', async () => {
    const refetch = vi.fn()
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: undefined, isLoading: false, isError: true, refetch }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-error')).toBeInTheDocument()
    // A failed trace request is `unavailable`, not an empty session — the state
    // is what stops the page reading as a clean bill of health.
    const status = screen.getByTestId('trace-unavailable')
    expect(status).toHaveAttribute('data-truth-state', 'unavailable')
    expect(status).toHaveTextContent('Trace unavailable')
    expect(screen.getByRole('alert')).toBe(status)

    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(refetch).toHaveBeenCalledTimes(1)
  })

  it('shows the shared EmptyState when the session has no events', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    const empty = screen.getByTestId('empty-state')
    expect(empty).toBeInTheDocument()
    expect(empty).toHaveTextContent('No events recorded for this session')
    // An empty session is a known answer, not an absence.
    expect(empty).toHaveAttribute('data-truth-state', 'empty')
    // Filter must not render when there are no events to filter.
    expect(screen.queryByTestId('trace-filter')).not.toBeInTheDocument()
  })

  it('mounts the timeline + filter when events carry a severity', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({
        data: [withSeverity('a', 'info')],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getByTestId('trace-filter')).toBeInTheDocument()
    expect(screen.getByTestId('trace-timeline')).toBeInTheDocument()
    expect(screen.getAllByTestId('trace-event')).toHaveLength(1)
  })

  it('mounts the timeline but no filter when no event has a known severity', () => {
    // The shape the real endpoint returns: `TraceSpan` has no severity field, so
    // every row is neutral and three of the filter's four boxes could never
    // match. Rendering it would be an affordance with no production path.
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({
        data: [MOCK_EVENT, { ...MOCK_EVENT, id: 'evt-2' }],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.queryByTestId('trace-filter')).not.toBeInTheDocument()
    expect(screen.getByTestId('trace-timeline')).toBeInTheDocument()
    const rows = screen.getAllByTestId('trace-event')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveAttribute('data-severity', 'neutral')
  })

  it('hides rows whose severity is unchecked in the filter', async () => {
    const events: TraceEvent[] = [
      { ...withSeverity('a', 'critical'), type: 'PolicyViolation' },
      { ...withSeverity('b', 'info'), type: 'ToolDispatched' },
    ]
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: events, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.getAllByTestId('trace-event')).toHaveLength(2)
    await userEvent.click(screen.getByTestId('trace-filter-info'))
    const remaining = screen.getAllByTestId('trace-event')
    expect(remaining).toHaveLength(1)
    expect(remaining[0]).toHaveAttribute('data-severity', 'critical')
  })

  it('shows the filter-empty state when every severity is unchecked', async () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({
        data: [
          withSeverity('a', 'critical'),
          withSeverity('b', 'warning'),
          withSeverity('c', 'info'),
          // Severity absent — this row is the `neutral` bucket.
          { ...MOCK_EVENT, id: 'd' },
        ],
        isLoading: false,
        isError: false,
        refetch: vi.fn(),
      }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    await userEvent.click(screen.getByTestId('trace-filter-critical'))
    await userEvent.click(screen.getByTestId('trace-filter-warning'))
    await userEvent.click(screen.getByTestId('trace-filter-info'))
    await userEvent.click(screen.getByTestId('trace-filter-neutral'))

    expect(screen.getByTestId('trace-filter-empty')).toBeInTheDocument()
    expect(screen.getByText('All events hidden by filter')).toBeInTheDocument()
    expect(screen.queryByTestId('trace-event')).not.toBeInTheDocument()
  })

  it('opens the PayloadModal when a timeline row is clicked, and closes on the close button', async () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    expect(screen.queryByTestId('payload-modal')).not.toBeInTheDocument()
    await userEvent.click(screen.getByTestId('trace-event'))
    expect(screen.getByTestId('payload-modal')).toBeInTheDocument()

    await userEvent.click(screen.getByTestId('payload-modal-close'))
    expect(screen.queryByTestId('payload-modal')).not.toBeInTheDocument()
  })

  it('renders the Export button only when events exist', () => {
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')
    expect(screen.queryByTestId('export-trace')).not.toBeInTheDocument()
  })

  it('Export button triggers downloadTraceJson with the trace ids and ALL events (not the filtered set)', async () => {
    const downloadSpy = vi.spyOn(traceExport, 'downloadTraceJson').mockImplementation(() => {})
    const events: TraceEvent[] = [withSeverity('a', 'critical'), withSeverity('b', 'info')]
    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: events, isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')

    // Filter to only critical — Export must still get both events.
    await userEvent.click(screen.getByTestId('trace-filter-info'))
    await userEvent.click(screen.getByTestId('export-trace'))

    expect(downloadSpy).toHaveBeenCalledOnce()
    const [agentId, sessionId, passedEvents] = downloadSpy.mock.calls[0]
    expect(agentId).toBe('agent-001')
    expect(sessionId).toBe('session-abc')
    expect(passedEvents).toHaveLength(2)
  })

  it('Export pipeline produces JSON that parses against traceExportSchema', async () => {
    let capturedBlobText = ''
    const originalCreateObjectURL = URL.createObjectURL
    const originalRevokeObjectURL = URL.revokeObjectURL
    URL.createObjectURL = vi.fn((blob: Blob) => {
      blob.text().then(text => { capturedBlobText = text })
      return 'blob:fake'
    })
    URL.revokeObjectURL = vi.fn()

    const originalCreateElement = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = originalCreateElement(tag)
      if (tag === 'a') el.click = vi.fn()
      return el
    })

    vi.spyOn(traceApi, 'useTraceQuery').mockReturnValue(
      mockTraceQuery({ data: [MOCK_EVENT], isLoading: false, isError: false, refetch: vi.fn() }),
    )
    renderAt('/agents/agent-001/trace/session-abc')
    await userEvent.click(screen.getByTestId('export-trace'))

    await new Promise(r => setTimeout(r, 0))
    const parsed = JSON.parse(capturedBlobText)
    expect(() => traceExportSchema.parse(parsed)).not.toThrow()
    expect(parsed.version).toBe('2')
    // The absences the page renders as `—` are written to the file as labelled
    // absences, not as zeroes or omitted keys.
    expect(parsed.events[0].severity).toEqual({
      known: false,
      state: 'not-supported',
      detail: NOT_ON_TRACE_SPAN,
    })

    URL.createObjectURL = originalCreateObjectURL
    URL.revokeObjectURL = originalRevokeObjectURL
  })
})
