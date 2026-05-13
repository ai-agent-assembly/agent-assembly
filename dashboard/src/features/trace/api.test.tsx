import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useTraceQuery } from './api'
import type { TraceEvent } from './types'

const MOCK_EVENTS: TraceEvent[] = [
  {
    id: 'evt-1',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'llm_call',
    agent: 'support-agent',
    durationMs: 834,
    payloadPreview: 'GPT-4o · query user #4521 billing',
    payload: { model: 'gpt-4o', prompt: 'lookup billing' },
    severity: 'info',
  },
  {
    id: 'evt-2',
    timestamp: '2026-04-23T14:23:16Z',
    type: 'policy_violation',
    agent: 'support-agent',
    durationMs: 12,
    payloadPreview: 'refund > $100 requires human approval',
    payload: { amount: 250, user_id: 4521 },
    severity: 'critical',
    redactedFields: ['user_id'],
  },
]

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useTraceQuery', () => {
  beforeEach(() => {
    localStorage.setItem('aa_token', 'test-token')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  it('returns events from a successful fetch and forwards the bearer token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(MOCK_EVENTS), { status: 200 }),
    )

    const { result } = renderHook(() => useTraceQuery('agent-1', 'session-1'), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(MOCK_EVENTS)
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/agents/agent-1/sessions/session-1/trace'),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    )
  })

  it('throws on non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 500 }))

    const { result } = renderHook(() => useTraceQuery('agent-1', 'session-1'), { wrapper })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch trace')
  })

  it('is disabled and does not fetch when ids are missing', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const { result } = renderHook(() => useTraceQuery('', ''), { wrapper })

    expect(result.current.fetchStatus).toBe('idle')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
