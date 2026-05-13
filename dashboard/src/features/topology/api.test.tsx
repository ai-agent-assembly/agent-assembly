import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useTopologyQuery } from './api'
import type { TopologyGraph } from './types'

const MOCK_GRAPH: TopologyGraph = {
  nodes: [
    {
      id: 'agent-1',
      name: 'support-agent',
      status: 'active',
      team: 'support',
      owner: 'alice',
      policyCount: 3,
      budgetSpend: 4.1,
      budgetLimit: 10,
      framework: 'langgraph',
    },
    {
      id: 'agent-2',
      name: 'data-analyst',
      status: 'idle',
      team: 'analytics',
      owner: 'carol',
      policyCount: 1,
      budgetSpend: 0,
      budgetLimit: 5,
    },
  ],
  edges: [
    { source: 'agent-1', target: 'agent-2', kind: 'delegation' },
  ],
}

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useTopologyQuery', () => {
  beforeEach(() => {
    localStorage.setItem('aa_token', 'test-token')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    localStorage.clear()
  })

  it('returns nodes + edges from a successful fetch and forwards the bearer token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(MOCK_GRAPH), { status: 200 }),
    )

    const { result } = renderHook(() => useTopologyQuery(), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(MOCK_GRAPH)
    expect(result.current.data?.nodes).toHaveLength(2)
    expect(result.current.data?.edges).toHaveLength(1)
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/topology'),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    )
  })

  it('throws on non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 503 }))

    const { result } = renderHook(() => useTopologyQuery(), { wrapper })

    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch topology')
  })

  it('returns an empty graph shape without crashing', async () => {
    const empty: TopologyGraph = { nodes: [], edges: [] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(empty), { status: 200 }),
    )

    const { result } = renderHook(() => useTopologyQuery(), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.nodes).toEqual([])
    expect(result.current.data?.edges).toEqual([])
  })
})
