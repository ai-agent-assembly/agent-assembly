import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useTopologyNodeRecentEvents, useTopologyQuery, type RecentEvent } from './api'
import { mapTopologyGraph } from './mapGraph'
import type { components } from '../../api/generated/schema'

// The wire shape the real `GET /api/v1/topology` endpoint returns (AAASM-5040):
// the `AgentNode` projection carrying live mode/flagged/trust badges, plus slim
// {source,target,kind} edges.
const API_GRAPH: components['schemas']['TopologyGraphResponse'] = {
  nodes: [
    { id: 'agent-1', name: 'support-agent', depth: 0, status: 'active', team_id: 'support', mode: 'shadow', flagged: true, trust: null },
    { id: 'agent-2', name: 'data-analyst', depth: 1, status: 'suspended', team_id: 'analytics', mode: 'enforce', flagged: false, trust: null },
  ],
  edges: [{ source: 'agent-1', target: 'agent-2', kind: 'delegation' }],
}

// What the hook returns after mapping the wire shape onto the view model.
const EXPECTED_GRAPH = mapTopologyGraph(API_GRAPH)

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useTopologyQuery', () => {
  beforeEach(() => {
    sessionStorage.setItem('aa_token', 'test-token')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('maps the endpoint response to the view model and forwards the bearer token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(API_GRAPH), { status: 200 }),
    )

    const { result } = renderHook(() => useTopologyQuery(), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(EXPECTED_GRAPH)
    expect(result.current.data?.nodes).toHaveLength(2)
    expect(result.current.data?.edges).toHaveLength(1)
    // Live badges flow through from the AgentNode projection (AAASM-5036).
    expect(result.current.data?.nodes[0].mode).toBe('shadow')
    expect(result.current.data?.nodes[0].flagged).toBe(true)
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
    const empty: components['schemas']['TopologyGraphResponse'] = { nodes: [], edges: [] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(empty), { status: 200 }),
    )

    const { result } = renderHook(() => useTopologyQuery(), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.nodes).toEqual([])
    expect(result.current.data?.edges).toEqual([])
  })
})

const MOCK_RECENT: RecentEvent[] = [
  { id: 'e1', timestamp: '2026-05-13T10:00:00Z', type: 'tool_call', message: 'query_db users' },
  { id: 'e2', timestamp: '2026-05-13T10:01:00Z', type: 'policy_violation', message: 'refund > $100' },
]

describe('useTopologyNodeRecentEvents', () => {
  beforeEach(() => {
    sessionStorage.setItem('aa_token', 'test-token')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
  })

  it('returns recent events for the given node id and forwards bearer token', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(MOCK_RECENT), { status: 200 }),
    )

    const { result } = renderHook(() => useTopologyNodeRecentEvents('agent-1'), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(MOCK_RECENT)
    expect(fetchSpy).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/topology/nodes/agent-1/events'),
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    )
  })

  it('throws on non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 503 }))
    const { result } = renderHook(() => useTopologyNodeRecentEvents('agent-1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch recent events')
  })

  it('is disabled and does not fetch when nodeId is empty', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    const { result } = renderHook(() => useTopologyNodeRecentEvents(''), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
