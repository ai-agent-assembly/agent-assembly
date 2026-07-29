import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { useAgentDecisionMixQuery } from './useAgentDecisionMixQuery'
import { api } from '../../api/client'

vi.mock('../../api/client', () => ({ api: { GET: vi.fn() } }))
const mockGet = vi.mocked(api.GET)

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function mixRow(agent_id: string, allow: number) {
  return { agent_id, allow, narrow: 0, scrub: 0, pending: 0, deny: 0 }
}

afterEach(() => vi.clearAllMocks())

describe('useAgentDecisionMixQuery', () => {
  it('returns the requested agent’s row out of the fleet-wide response', async () => {
    mockGet.mockResolvedValue({
      data: [mixRow('other', 1), mixRow('wanted', 42)],
      error: undefined,
    } as unknown as ReturnType<typeof api.GET>)

    const { result } = renderHook(() => useAgentDecisionMixQuery('wanted'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.agent_id).toBe('wanted')
    expect(result.current.data?.allow).toBe(42)
    // The window default is threaded to the wire.
    expect(mockGet).toHaveBeenCalledWith('/api/v1/analytics/agent-decision-mix', {
      params: { query: { window: '24h' } },
    })
  })

  it('returns null (truthful no-data) when the agent is absent from the response', async () => {
    mockGet.mockResolvedValue({
      data: [mixRow('someone-else', 5)],
      error: undefined,
    } as unknown as ReturnType<typeof api.GET>)

    const { result } = renderHook(() => useAgentDecisionMixQuery('missing'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeNull()
  })

  it('throws when the endpoint returns an error', async () => {
    mockGet.mockResolvedValue({ data: undefined, error: { message: 'boom' } } as unknown as ReturnType<typeof api.GET>)

    const { result } = renderHook(() => useAgentDecisionMixQuery('wanted'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent decision mix')
  })

  it('does not query with an empty agent id', () => {
    renderHook(() => useAgentDecisionMixQuery(''), { wrapper })
    expect(mockGet).not.toHaveBeenCalled()
  })
})
