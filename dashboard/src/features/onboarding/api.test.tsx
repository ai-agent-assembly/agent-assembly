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

  it('reports a 503 as an error naming the degraded subsystems', async () => {
    apiGet.mockResolvedValue(failure(503, DEGRADED))

    const outcome = await probeGatewayHealth()

    expect(outcome.isError).toBe(true)
    expect(outcome.data).toBeUndefined()
    expect((outcome.error as Error).message).toBe(
      'HTTP 503 — degraded: policy_engine, audit_pipeline',
    )
  })

  it('falls back to the bare status when the error body carries no checks map', async () => {
    apiGet.mockResolvedValue(failure(500, { detail: 'internal' }))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 500')
  })

  it('falls back to the bare status when the error body is not an object at all', async () => {
    apiGet.mockResolvedValue(failure(502, 'bad gateway'))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 502')
  })

  it('falls back to the bare status when checks is present but not an object', async () => {
    apiGet.mockResolvedValue(failure(503, { checks: 'degraded' }))

    expect(((await probeGatewayHealth()).error as Error).message).toBe('HTTP 503')
  })

  it('falls back to the bare status when every subsystem in the map reports ok', async () => {
    apiGet.mockResolvedValue(failure(503, HEALTHY))

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
