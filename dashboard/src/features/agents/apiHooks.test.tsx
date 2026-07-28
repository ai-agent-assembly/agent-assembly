import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  useAgentCapabilitiesQuery,
  useAgentDecisionsQuery,
  useAgentEnforcementQuery,
  useAgentEventsQuery,
  useAgentQuery,
  useAgentSubtreeBurnQuery,
  useAgentsQuery,
} from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

let get: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useAgentsQuery', () => {
  it('requests up to 100 agents and returns the list', async () => {
    // AAASM-4892: /agents returns a paginated { items, total } object.
    get.mockResolvedValue({ data: { items: [{ id: 'a1' }], page: 1, per_page: 100, total: 1 } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ id: 'a1' }])
    expect(get).toHaveBeenCalledWith('/api/v1/agents', { params: { query: { per_page: 100 } } })
  })

  it('falls back to an empty array when data is nullish', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agents')
  })
})

describe('useAgentEnforcementQuery', () => {
  it('defaults to the 24h window and folds rows into a lookup keyed by agent id', async () => {
    get.mockResolvedValue({
      data: [
        { agent_id: 'a1', blocked: 3, scrubbed: 1 },
        { agent_id: 'a2', blocked: 0, scrubbed: 5 },
      ],
    } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEnforcementQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(
      new Map([
        ['a1', { blocked: 3, scrubbed: 1 }],
        ['a2', { blocked: 0, scrubbed: 5 }],
      ]),
    )
    expect(get).toHaveBeenCalledWith('/api/v1/analytics/agent-enforcement', {
      params: { query: { window: '24h' } },
    })
  })

  it('passes an explicit window through to the endpoint', async () => {
    get.mockResolvedValue({ data: [] } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEnforcementQuery('7d'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/analytics/agent-enforcement', {
      params: { query: { window: '7d' } },
    })
  })

  it('returns an empty lookup when the response body is nullish', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEnforcementQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(new Map())
  })

  it('retrieves an inherited-prototype agent_id via .get() instead of colliding with it', async () => {
    // AAASM-5237: agent_id is raw wire input. With the old plain-object
    // accumulator, `constructor` would read back `Object` and `__proto__`
    // would write through the prototype setter instead of storing an ordinary
    // entry. A Map treats both as ordinary keys.
    get.mockResolvedValue({
      data: [
        { agent_id: 'constructor', blocked: 9, scrubbed: 2 },
        { agent_id: '__proto__', blocked: 4, scrubbed: 1 },
      ],
    } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEnforcementQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    const lookup = result.current.data
    expect(lookup?.get('constructor')).toEqual({ blocked: 9, scrubbed: 2 })
    expect(lookup?.get('__proto__')).toEqual({ blocked: 4, scrubbed: 1 })
    expect(lookup?.size).toBe(2)
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEnforcementQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent enforcement metrics')
  })
})

describe('useAgentQuery', () => {
  it('is disabled when the id is empty', () => {
    const { result } = renderHook(() => useAgentQuery(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
    expect(get).not.toHaveBeenCalled()
  })

  it('fetches the agent by id on success', async () => {
    get.mockResolvedValue({ data: { id: 'a1' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}', { params: { path: { id: 'a1' } } })
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent')
  })
})

describe('useAgentSubtreeBurnQuery', () => {
  it('defaults to the 7d period', async () => {
    get.mockResolvedValue({ data: { total_usd: 1 } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentSubtreeBurnQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}/subtree-burn', {
      params: { path: { id: 'a1' }, query: { period: '7d' } },
    })
  })

  it('throws "empty" when data is missing', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentSubtreeBurnQuery('a1', '30d'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Subtree burn response was empty')
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentSubtreeBurnQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch subtree burn')
  })
})

describe('useAgentCapabilitiesQuery', () => {
  it('returns capabilities on success', async () => {
    get.mockResolvedValue({ data: { permissions: [] } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentCapabilitiesQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}/capabilities', {
      params: { path: { id: 'a1' } },
    })
  })

  it('throws "empty" when data is missing', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentCapabilitiesQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Agent capabilities response was empty')
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentCapabilitiesQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent capabilities')
  })
})

describe('useAgentDecisionsQuery', () => {
  it('requests the decision stream with the default limit and returns rows', async () => {
    get.mockResolvedValue({ data: { decisions: [{ seq: 1 }] } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentDecisionsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ seq: 1 }])
    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}/decisions', {
      params: { path: { id: 'a1' }, query: { limit: 50 } },
    })
  })

  it('passes an explicit limit through to the endpoint', async () => {
    get.mockResolvedValue({ data: { decisions: [] } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentDecisionsQuery('a1', 10), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}/decisions', {
      params: { path: { id: 'a1' }, query: { limit: 10 } },
    })
  })

  it('falls back to an empty array when the response body is nullish', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentDecisionsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('is disabled when the id is empty', () => {
    const { result } = renderHook(() => useAgentDecisionsQuery(''), { wrapper: makeWrapper() })
    expect(result.current.fetchStatus).toBe('idle')
    expect(get).not.toHaveBeenCalled()
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentDecisionsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent decisions')
  })
})

describe('useAgentEventsQuery', () => {
  it('requests the agent log feed and returns entries', async () => {
    get.mockResolvedValue({ data: [{ seq: 1 }] } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEventsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', {
      params: { query: { agent_id: 'a1', per_page: 50 } },
    })
  })

  it('falls back to an empty array when data is nullish', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEventsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentEventsQuery('a1'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent events')
  })
})
