import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { useCostHistoryQuery, useBudgetTreeQuery } from './api'

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

describe('useCostHistoryQuery', () => {
  it('requests the endpoint with the days window and returns the response', async () => {
    const payload = { days: 7, points: [{ date: '2026-05-11', spend_usd: '4.00' }] }
    get.mockResolvedValue({ data: payload } satisfies FetchResult)
    const { result } = renderHook(() => useCostHistoryQuery(7), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(payload)
    expect(get).toHaveBeenCalledWith('/api/v1/costs/history', { params: { query: { days: 7 } } })
  })

  it('throws when the client returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useCostHistoryQuery(30), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch cost history')
  })

  it('throws when the response body is empty', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useCostHistoryQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Cost history response was empty')
  })
})

describe('useBudgetTreeQuery', () => {
  it('requests the endpoint and returns the response', async () => {
    const payload = { root: null }
    get.mockResolvedValue({ data: payload } satisfies FetchResult)
    const { result } = renderHook(() => useBudgetTreeQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(payload)
    expect(get).toHaveBeenCalledWith('/api/v1/costs/budget-tree', {})
  })

  it('throws when the client returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useBudgetTreeQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch budget tree')
  })

  it('throws when the response body is empty', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useBudgetTreeQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Budget tree response was empty')
  })
})
