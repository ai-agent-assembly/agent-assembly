/**
 * `api/client` is mocked rather than `globalThis.fetch` spied on: `openapi-fetch`
 * captures `globalThis.fetch` when `createClient` runs at module load, so a spy
 * installed afterwards is never consulted (the same gotcha that forces the
 * Playwright specs onto `page.route`). Mocking the client also puts the tests on
 * the boundary that matters here — the `{ data, error, response }` triple this
 * module has to classify.
 */
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../api/client'
import {
  ENROLLED_AGENTS_POLL_MS,
  probeGatewayHealth,
  useRegisteredAgentsQuery,
  type GatewayHealth,
  type RegisteredAgent,
} from './api'

vi.mock('../../api/client', () => ({ api: { GET: vi.fn() } }))

const apiGet = api.GET as unknown as ReturnType<typeof vi.fn>

/** The subset of `Response` this module reads. */
function res(status: number): Response {
  return { ok: status >= 200 && status < 300, status } as Response
}

function ok<T>(data: T) {
  return { data, error: undefined, response: res(200) }
}

function failure(status: number, error: unknown) {
  return { data: undefined, error, response: res(status) }
}

const HEALTHY: GatewayHealth = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 1200,
  active_connections: 0,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok', policy_engine: 'ok' },
}

const DEGRADED: GatewayHealth = {
  ...HEALTHY,
  status: 'degraded',
  checks: { storage: 'ok', policy_engine: 'degraded', audit_pipeline: 'degraded' },
}

const AGENT: RegisteredAgent = {
  id: 'agent-1',
  name: 'research-bot',
  framework: 'langgraph',
  version: '0.0.1',
  status: 'active',
  tool_names: [],
  metadata: {},
  session_count: 0,
  policy_violations_count: 0,
  active_sessions: [],
  recent_events: [],
  recent_traces: [],
  last_event: '2026-07-26T09:00:00Z',
  layer: null,
  pid: null,
}

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

beforeEach(() => {
  apiGet.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('probeGatewayHealth', () => {
  it('returns the health payload when the gateway answers 200', async () => {
    apiGet.mockResolvedValue(ok(HEALTHY))

    const outcome = await probeGatewayHealth()

    expect(apiGet).toHaveBeenCalledWith('/api/v1/health')
    expect(outcome.isError).toBeUndefined()
    expect(outcome.data).toEqual(HEALTHY)
  })

  // ── The 503-with-body path ────────────────────────────────────────────────
  // `aa-api/src/routes/health.rs` derives the 503 and the "degraded" status
  // string from the same `all_ok` boolean, so a degraded gateway *always*
  // answers 503 carrying a complete HealthResponse. That is an answer. Routing
  // it to `unavailable` would assert we heard nothing from a gateway that had
  // just named the broken subsystem.

  it('treats a 503 carrying a HealthResponse as an answer, not as silence', async () => {
    apiGet.mockResolvedValue(failure(503, DEGRADED))

    const outcome = await probeGatewayHealth()

    expect(outcome.isError).toBeUndefined()
    expect(outcome.error).toBeUndefined()
    expect(outcome.data).toEqual(DEGRADED)
    // The subsystem report survives intact — it is the actionable part.
    expect(outcome.data?.checks).toEqual(DEGRADED.checks)
  })

  it('declines a 503 whose body is a ProblemDetail rather than a health report', async () => {
    apiGet.mockResolvedValue(failure(503, { type: 'about:blank', title: 'Unavailable', status: 503 }))

    const outcome = await probeGatewayHealth()

    expect(outcome.isError).toBe(true)
    expect((outcome.error as Error).message).toBe('HTTP 503')
  })

  it('declines a body that is not an object at all — a proxy error page', async () => {
    apiGet.mockResolvedValue(failure(502, '<html>502 Bad Gateway</html>'))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 502')
  })

  it('declines a body whose checks is present but not a map of strings', async () => {
    apiGet.mockResolvedValue(
      failure(503, { ...DEGRADED, checks: { storage: { state: 'degraded' } } }),
    )

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 503')
  })

  it('declines a body missing the version fields a health report always carries', async () => {
    apiGet.mockResolvedValue(failure(503, { status: 'degraded', checks: { storage: 'degraded' } }))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 503')
  })

  it('declines a body whose checks is an array rather than a map', async () => {
    apiGet.mockResolvedValue(failure(503, { ...DEGRADED, checks: ['storage'] }))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 503')
  })

  it('declines a body whose status is an empty string', async () => {
    apiGet.mockResolvedValue(failure(503, { ...DEGRADED, status: '' }))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 503')
  })

  it('reports a rejected request — the gateway-down case — as an error, never a success', async () => {
    apiGet.mockRejectedValue(new TypeError('Failed to fetch'))

    const outcome = await probeGatewayHealth()

    expect(outcome.isError).toBe(true)
    expect(outcome.data).toBeUndefined()
    expect((outcome.error as Error).message).toBe('Failed to fetch')
  })

  it('wraps a non-Error rejection so the caller always gets a message', async () => {
    apiGet.mockRejectedValue('socket hang up')

    expect(((await probeGatewayHealth()).error as Error).message).toBe('socket hang up')
  })

  it('reports a 200 with no body as an empty payload rather than a health record', async () => {
    apiGet.mockResolvedValue({ data: undefined, error: undefined, response: res(200) })

    const outcome = await probeGatewayHealth()

    expect(outcome.isError).toBeUndefined()
    expect(outcome.data).toBeNull()
  })
})

describe('useRegisteredAgentsQuery', () => {
  it('returns the registry total and the first page of agents', async () => {
    apiGet.mockResolvedValue(ok({ items: [AGENT], page: 1, per_page: 100, total: 1 }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual({ total: 1, items: [AGENT] })
    expect(apiGet).toHaveBeenCalledWith('/api/v1/agents', {
      params: { query: { per_page: 100 } },
    })
  })

  it('keeps a real, measured zero — an answered registry holding no agents', async () => {
    apiGet.mockResolvedValue(ok({ items: [], page: 1, per_page: 100, total: 0 }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual({ total: 0, items: [] })
  })

  it('throws on a non-OK response rather than reporting zero agents', async () => {
    apiGet.mockResolvedValue(failure(503, { detail: 'boom' }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), { wrapper })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch registered agents')
    expect(result.current.data).toBeUndefined()
  })

  it('surfaces a failure on the first attempt rather than retrying behind a backoff', async () => {
    // A retry chain would hold the step at "Request in flight" while the
    // registry was already known to be failing. Asserted against a client that
    // *would* retry, so the hook's own `retry: false` is what is under test.
    const retryingClient = new QueryClient({ defaultOptions: { queries: { retry: 3 } } })
    const retryingWrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={retryingClient}>{children}</QueryClientProvider>
    )
    apiGet.mockResolvedValue(failure(503, { detail: 'boom' }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), {
      wrapper: retryingWrapper,
    })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(apiGet).toHaveBeenCalledTimes(1)
  })

  it('throws when a 200 carries no payload, rather than coercing it to total 0', async () => {
    apiGet.mockResolvedValue({ data: undefined, error: undefined, response: res(200) })

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), { wrapper })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Agent registry returned no payload')
  })

  it('does not touch the gateway while disabled', () => {
    apiGet.mockResolvedValue(ok({ items: [], page: 1, per_page: 100, total: 0 }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(false), { wrapper })

    expect(result.current.fetchStatus).toBe('idle')
    expect(apiGet).not.toHaveBeenCalled()
  })

  it('re-asks on an interval so a late registration is picked up', async () => {
    vi.useFakeTimers()
    apiGet.mockResolvedValue(ok({ items: [], page: 1, per_page: 100, total: 0 }))

    const { result } = renderHook(() => useRegisteredAgentsQuery(true), { wrapper })
    await vi.waitFor(() => expect(result.current.isSuccess).toBe(true))
    const firstCallCount = apiGet.mock.calls.length

    await vi.advanceTimersByTimeAsync(ENROLLED_AGENTS_POLL_MS + 50)

    expect(apiGet.mock.calls.length).toBeGreaterThan(firstCallCount)
    vi.useRealTimers()
  })
})
