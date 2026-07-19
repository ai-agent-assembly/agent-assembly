import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  useAgentCapabilitiesQuery,
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
