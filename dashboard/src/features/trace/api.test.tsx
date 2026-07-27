import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import { isAbsent, isKnown } from '../../lib/truthfulness'
import { TRACE_PATH, mapSpanToEvent, spanDurationMs, useTraceQuery } from './api'

vi.mock('../../api/client', () => ({ api: { GET: vi.fn() } }))

const mockGet = vi.mocked(api.GET)

type Span = Parameters<typeof mapSpanToEvent>[0]

function span(overrides: Partial<Span> = {}): Span {
  return {
    span_id: 'span-1',
    operation: 'ToolCallIntercepted',
    start_time: '2026-04-23T14:23:01.000Z',
    ...overrides,
  }
}

function traceResponse(spans: Span[]) {
  return {
    data: { session_id: 'session-1', agent_id: 'agent-001', spans },
    error: undefined,
  }
}

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('the route the trace surface calls', () => {
  it('is the one path the OpenAPI schema declares', () => {
    // AAASM-5109 — `openapi/v1.yaml` declares `/api/v1/traces/{session_id}`
    // (operationId `get_trace`) and no `/agents/{id}/sessions/{sid}/trace` path
    // of any kind. Pinning the literal here means a drift back to the
    // non-existent route fails this test rather than 404-ing in production.
    expect(TRACE_PATH).toBe('/api/v1/traces/{session_id}')
    expect(TRACE_PATH).not.toContain('/sessions/')
  })

  it('requests that path, keyed by session alone', async () => {
    mockGet.mockResolvedValue(traceResponse([span()]))

    const { result } = renderHook(() => useTraceQuery('session-1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(mockGet).toHaveBeenCalledWith(TRACE_PATH, {
      params: { path: { session_id: 'session-1' } },
    })
  })

  it('does not fetch without a session id', () => {
    const { result } = renderHook(() => useTraceQuery(''), { wrapper })

    expect(result.current.fetchStatus).toBe('idle')
    expect(mockGet).not.toHaveBeenCalled()
  })

  it('throws when the trace cannot be read, rather than reporting an empty session', async () => {
    // A session that could not be read is not a session with no spans; the page
    // renders those two as different states, which only works if this throws.
    mockGet.mockResolvedValue({ data: undefined, error: { detail: 'not found' } })

    const { result } = renderHook(() => useTraceQuery('session-1'), { wrapper })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to load trace')
    expect(result.current.data).toBeUndefined()
  })
})

describe('spanDurationMs', () => {
  it('measures a completed span', () => {
    const duration = spanDurationMs(
      span({ start_time: '2026-04-23T14:23:01.000Z', end_time: '2026-04-23T14:23:01.834Z' }),
    )
    expect(isKnown(duration) && duration.value).toBe(834)
  })

  it('keeps a measured zero as a real value', () => {
    // A span that started and ended within the same millisecond took 0 ms, and
    // that is a fact — `certain`-style falsy-collapsing would have lost it.
    const duration = spanDurationMs(
      span({ start_time: '2026-04-23T14:23:01.000Z', end_time: '2026-04-23T14:23:01.000Z' }),
    )
    expect(isKnown(duration)).toBe(true)
    expect(isKnown(duration) && duration.value).toBe(0)
  })

  it.each([
    ['a null end time — the shape the audit reconstruction emits', { end_time: null }],
    ['an omitted end time', {}],
    ['an empty end time', { end_time: '' }],
  ])('reports %s as unknown rather than as a number', (_label, overrides) => {
    const duration = spanDurationMs(span(overrides))
    expect(isAbsent(duration)).toBe(true)
    expect(isAbsent(duration) && duration.state).toBe('unknown')
  })

  it('refuses to produce NaN from an unparseable timestamp', () => {
    // `Date.parse` returns NaN here; the old code would have rendered the
    // subtraction straight into the DOM as "NaN ms" (AAASM-5165).
    const duration = spanDurationMs(span({ end_time: 'not-a-date' }))
    expect(isAbsent(duration)).toBe(true)
    expect(isAbsent(duration) && duration.state).toBe('unknown')
  })

  it('rejects a span that ended before it started', () => {
    const duration = spanDurationMs(
      span({ start_time: '2026-04-23T14:23:05.000Z', end_time: '2026-04-23T14:23:01.000Z' }),
    )
    expect(isAbsent(duration)).toBe(true)
  })
})

describe('mapSpanToEvent', () => {
  it('maps every field the wire actually carries', () => {
    const event = mapSpanToEvent(
      span({
        span_id: 'span-9',
        parent_span_id: 'span-1',
        operation: 'PolicyViolation',
        decision: 'deny',
        end_time: '2026-04-23T14:23:01.012Z',
      }),
      'agent-001',
    )

    expect(event.id).toBe('span-9')
    expect(event.type).toBe('PolicyViolation')
    expect(event.timestamp).toBe('2026-04-23T14:23:01.000Z')
    expect(event.parentSpanId).toBe('span-1')
    // The agent comes from the envelope, not from the span.
    expect(event.agent).toBe('agent-001')
    expect(isKnown(event.durationMs) && event.durationMs.value).toBe(12)
    expect(isKnown(event.decision) && event.decision.value).toBe('deny')
  })

  it('treats a root span as having no parent', () => {
    expect(mapSpanToEvent(span({ parent_span_id: null }), 'agent-001').parentSpanId).toBeNull()
  })

  it.each([
    ['null', { decision: null }],
    ['omitted', {}],
    ['empty', { decision: '' }],
  ])('reports a %s decision as not-evaluated', (_label, overrides) => {
    const { decision } = mapSpanToEvent(span(overrides), 'agent-001')
    expect(isAbsent(decision) && decision.state).toBe('not-evaluated')
  })

  it.each([
    'payload',
    'payloadPreview',
    'severity',
    'redactedFields',
    'violationReason',
  ] as const)('reports %s as not-supported, because TraceSpan has no such field', (field) => {
    const event = mapSpanToEvent(span(), 'agent-001')
    const value = event[field]
    expect(isAbsent(value)).toBe(true)
    // `not-supported`, not `unknown`: no amount of retrying makes the schema
    // grow the field. Waiting on AAASM-5100 is the only path.
    expect(isAbsent(value) && value.state).toBe('not-supported')
    expect(isAbsent(value) && value.detail).toBeTruthy()
  })

  it('maps a whole response through the hook', async () => {
    mockGet.mockResolvedValue(
      traceResponse([span({ span_id: 'a' }), span({ span_id: 'b', operation: 'PolicyViolation' })]),
    )

    const { result } = renderHook(() => useTraceQuery('session-1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(result.current.data).toHaveLength(2)
    expect(result.current.data?.map((e) => e.id)).toEqual(['a', 'b'])
    expect(result.current.data?.every((e) => e.agent === 'agent-001')).toBe(true)
  })
})
