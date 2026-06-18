import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { useApprovalsQuery, useApproveAction, useRejectAction } from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

let get: Mock
let post: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useApprovalsQuery', () => {
  it('requests up to 100 items and returns the items array', async () => {
    get.mockResolvedValue({ data: { items: [{ id: 'a1' }] } } satisfies FetchResult)
    const { result } = renderHook(() => useApprovalsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([{ id: 'a1' }])
    expect(get).toHaveBeenCalledWith('/api/v1/approvals', {
      params: { query: { per_page: 100 } },
    })
  })

  it('falls back to an empty array when items is absent', async () => {
    get.mockResolvedValue({ data: {} } satisfies FetchResult)
    const { result } = renderHook(() => useApprovalsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useApprovalsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch approvals')
  })
})

describe('useApproveAction', () => {
  it('POSTs the approval id and optional approver', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'approved' } } satisfies FetchResult)
    const { result } = renderHook(() => useApproveAction(), { wrapper: makeWrapper() })
    const out = await result.current.mutateAsync({ id: 'a1', by: 'alice' })
    expect(out).toEqual({ id: 'a1', status: 'approved' })
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/approve', {
      params: { path: { id: 'a1' } },
      body: { by: 'alice' },
    })
  })

  it('throws on failure', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useApproveAction(), { wrapper: makeWrapper() })
    await expect(result.current.mutateAsync({ id: 'a1' })).rejects.toThrow('Failed to approve')
  })
})

describe('useRejectAction', () => {
  it('POSTs the rejection reason', async () => {
    post.mockResolvedValue({ data: { id: 'a1', status: 'rejected' } } satisfies FetchResult)
    const { result } = renderHook(() => useRejectAction(), { wrapper: makeWrapper() })
    await result.current.mutateAsync({ id: 'a1', reason: 'unsafe', by: 'bob' })
    expect(post).toHaveBeenCalledWith('/api/v1/approvals/{id}/reject', {
      params: { path: { id: 'a1' } },
      body: { reason: 'unsafe', by: 'bob' },
    })
  })

  it('throws on failure', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useRejectAction(), { wrapper: makeWrapper() })
    await expect(
      result.current.mutateAsync({ id: 'a1', reason: 'unsafe' }),
    ).rejects.toThrow('Failed to reject')
  })
})
