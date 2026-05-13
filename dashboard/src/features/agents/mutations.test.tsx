import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest'
import { useSuspendAgent, useResumeAgent } from './mutations'
import { api } from '../../api/client'

interface FetchOk<T> { data: T; error?: never }
interface FetchErr { data?: never; error: Error }

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return {
    client,
    wrapper: ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  }
}

afterEach(() => { vi.restoreAllMocks() })

describe('useSuspendAgent', () => {
  let post: Mock
  beforeEach(() => {
    post = vi.spyOn(api, 'POST') as unknown as Mock
  })

  it('rejects an empty reason without calling the gateway', async () => {
    post.mockResolvedValue({ data: undefined, error: new Error('should not be called') } satisfies FetchErr)
    const { result } = renderHook(() => useSuspendAgent(), makeWrapper())
    result.current.mutate({ id: 'a', reason: '   ' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toContain('non-empty reason')
    expect(post).not.toHaveBeenCalled()
  })

  it('POSTs the trimmed reason to /agents/:id/suspend on success', async () => {
    post.mockResolvedValue({
      data: { agent_id: 'a', previous_status: 'active', new_status: 'suspended' },
    } satisfies FetchOk<unknown>)
    const { result } = renderHook(() => useSuspendAgent(), makeWrapper())
    result.current.mutate({ id: 'a', reason: '  manual override  ' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/suspend', {
      params: { path: { id: 'a' } },
      body: { reason: 'manual override' },
    })
  })

  it('surfaces gateway errors to the caller', async () => {
    post.mockResolvedValue({ error: { message: 'bad request' } } as unknown as FetchErr)
    const { result } = renderHook(() => useSuspendAgent(), makeWrapper())
    result.current.mutate({ id: 'a', reason: 'noop' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to suspend agent')
  })

  it('invalidates the agents list and the targeted agent on success', async () => {
    post.mockResolvedValue({
      data: { agent_id: 'a', previous_status: 'active', new_status: 'suspended' },
    } satisfies FetchOk<unknown>)
    const { client, wrapper } = makeWrapper()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useSuspendAgent(), { wrapper })
    result.current.mutate({ id: 'agent-1', reason: 'manual' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents', 'agent-1'] })
  })
})

describe('useResumeAgent', () => {
  let post: Mock
  beforeEach(() => {
    post = vi.spyOn(api, 'POST') as unknown as Mock
  })

  it('POSTs /agents/:id/resume with no body on success', async () => {
    post.mockResolvedValue({
      data: { agent_id: 'a', previous_status: 'suspended', new_status: 'active' },
    } satisfies FetchOk<unknown>)
    const { result } = renderHook(() => useResumeAgent(), makeWrapper())
    result.current.mutate({ id: 'a' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/resume', {
      params: { path: { id: 'a' } },
    })
  })

  it('surfaces gateway errors', async () => {
    post.mockResolvedValue({ error: { message: 'gone' } } as unknown as FetchErr)
    const { result } = renderHook(() => useResumeAgent(), makeWrapper())
    result.current.mutate({ id: 'a' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to resume agent')
  })

  it('invalidates the agents list and the targeted agent on success', async () => {
    post.mockResolvedValue({
      data: { agent_id: 'a', previous_status: 'suspended', new_status: 'active' },
    } satisfies FetchOk<unknown>)
    const { client, wrapper } = makeWrapper()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useResumeAgent(), { wrapper })
    result.current.mutate({ id: 'agent-7' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents', 'agent-7'] })
  })
})
