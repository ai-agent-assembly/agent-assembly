import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest'
import {
  useSuspendAgent,
  useResumeAgent,
  useSetEnforcementMode,
  usePreviewEnforcementCascade,
  EnforcementModeError,
} from './mutations'
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
    post.mockResolvedValue({ error: { message: 'bad request' } })
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
    post.mockResolvedValue({ error: { message: 'gone' } })
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

describe('useSetEnforcementMode', () => {
  let post: Mock
  beforeEach(() => {
    post = vi.spyOn(api, 'POST') as unknown as Mock
  })

  it('strengthens with mode="enforce" and no reason/expiry in the body', async () => {
    post.mockResolvedValue({
      data: { agent_id: 'a', new_mode: 'enforce' },
    } satisfies FetchOk<unknown>)
    const { result } = renderHook(() => useSetEnforcementMode(), makeWrapper())
    result.current.mutate({ id: 'a', mode: 'enforce' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/enforcement-mode', {
      params: { path: { id: 'a' } },
      body: { mode: 'enforce' },
    })
  })

  it('forwards reason, expires_at, and the cascade echo-back on a weaken', async () => {
    post.mockResolvedValue({
      data: { affected_ids: ['a', 'b'], count: 2, new_mode: 'observe' },
    } satisfies FetchOk<unknown>)
    const { result } = renderHook(() => useSetEnforcementMode(), makeWrapper())
    result.current.mutate({
      id: 'a',
      mode: 'observe',
      reason: 'incident triage',
      expiresAt: '2026-08-02T00:00:00.000Z',
      cascade: { expected_ids: ['a', 'b'], expected_count: 2 },
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/enforcement-mode', {
      params: { path: { id: 'a' } },
      body: {
        mode: 'observe',
        reason: 'incident triage',
        expires_at: '2026-08-02T00:00:00.000Z',
        cascade: { expected_ids: ['a', 'b'], expected_count: 2 },
      },
    })
  })

  it('invalidates topology and the agent queries on success', async () => {
    post.mockResolvedValue({ data: { agent_id: 'a', new_mode: 'enforce' } } satisfies FetchOk<unknown>)
    const { client, wrapper } = makeWrapper()
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useSetEnforcementMode(), { wrapper })
    result.current.mutate({ id: 'agent-9', mode: 'enforce' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['topology'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['agents', 'agent-9'] })
  })

  it.each([
    [403, 'Admin scope'],
    [409, 're-preview'],
    [422, 'reason or expiry'],
    [undefined, 'Failed to change enforcement mode'],
  ])('maps status %s to an operator message and carries the status', async (status, fragment) => {
    post.mockResolvedValue({ error: { message: 'server' }, response: { status } })
    const { result } = renderHook(() => useSetEnforcementMode(), makeWrapper())
    result.current.mutate({ id: 'a', mode: 'observe' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    const err = result.current.error
    expect(err).toBeInstanceOf(EnforcementModeError)
    expect(err?.status).toBe(status)
    expect(err?.message).toContain(fragment)
  })
})

describe('usePreviewEnforcementCascade', () => {
  let post: Mock
  beforeEach(() => {
    post = vi.spyOn(api, 'POST') as unknown as Mock
  })

  it('returns the affected set on success', async () => {
    post.mockResolvedValue({
      data: { affected_ids: ['a', 'b', 'c'], count: 3 },
    } satisfies FetchOk<unknown>)
    const { result } = renderHook(() => usePreviewEnforcementCascade(), makeWrapper())
    result.current.mutate({ id: 'a' })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/enforcement-mode/preview', {
      params: { path: { id: 'a' } },
    })
    expect(result.current.data).toEqual({ affected_ids: ['a', 'b', 'c'], count: 3 })
  })

  it('surfaces the over-cap 422 and the cross-tenant 403 from the server', async () => {
    post.mockResolvedValue({ error: { message: 'server' }, response: { status: 422 } })
    const { result } = renderHook(() => usePreviewEnforcementCascade(), makeWrapper())
    result.current.mutate({ id: 'a' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.status).toBe(422)
    expect(result.current.error?.message).toContain('maximum affected-agent count')
  })

  it('treats a missing data body as an error rather than a silent empty preview', async () => {
    post.mockResolvedValue({ data: undefined, response: { status: 200 } })
    const { result } = renderHook(() => usePreviewEnforcementCascade(), makeWrapper())
    result.current.mutate({ id: 'a' })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error).toBeInstanceOf(EnforcementModeError)
  })
})
