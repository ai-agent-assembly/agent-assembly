import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { useEnforcementTimelineQuery } from './api'

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

describe('useEnforcementTimelineQuery', () => {
  it('requests the endpoint with the window and returns the response', async () => {
    const payload = { window: '7d', bucketSecs: 25200, buckets: [] }
    get.mockResolvedValue({ data: payload } satisfies FetchResult)
    const { result } = renderHook(() => useEnforcementTimelineQuery('7d'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(payload)
    expect(get).toHaveBeenCalledWith('/api/v1/overview/enforcement-timeline', {
      params: { query: { window: '7d' } },
    })
  })

  it('throws when the client returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useEnforcementTimelineQuery('24h'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch enforcement timeline')
  })

  it('throws when the response body is empty', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useEnforcementTimelineQuery('1h'), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Enforcement timeline response was empty')
  })
})
