import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useTopologyNodeRecentEvents, useTopologyQuery, type RecentEvent } from './api'
import { mapTopologyGraph } from './mapGraph'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

// The wire shape the real `GET /api/v1/topology` endpoint returns (AAASM-5040,
// widened in AAASM-5099): the `AgentNode` projection carrying live
// mode/flagged/trust badges and the policy-inheritance chain, plus
// {source,target,kind,cross_team} edges in all six relation kinds.
const API_GRAPH: components['schemas']['TopologyGraphResponse'] = {
  nodes: [
    {
      id: 'agent-1',
      name: 'support-agent',
      depth: 0,
      status: 'active',
      team_id: 'support',
      mode: 'shadow',
      flagged: true,
      trust: null,
      effective_permissions: {
        chain: [
          { tier: 'global', scope: 'global', policies: ['baseline'] },
          { tier: 'team', scope: 'team:support', policies: [] },
        ],
        allow: [],
        deny: ['terminal_exec'],
        allow_restricted: false,
        cascade_loaded: true,
      },
    },
    { id: 'agent-2', name: 'data-analyst', depth: 1, status: 'suspended', team_id: 'analytics', mode: 'enforce', flagged: false, trust: null },
  ],
  edges: [
    { source: 'agent-1', target: 'agent-2', kind: 'delegation', cross_team: true },
    { source: 'agent-2', target: 'agent-1', kind: 'reads', cross_team: true },
    { source: 'agent-1', target: 'agent-1', kind: 'approves', cross_team: false },
  ],
  unclaimed_observable: true,
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
    // `useTopologyQuery` composes the per-agent trust rollup (AAASM-5083) via
    // the typed `api` client. Stub it to an empty response so it never touches
    // the `globalThis.fetch` spy — otherwise the trust GET would be counted by
    // the poll-cadence assertions and parse the graph body as a TrustResponse.
    vi.spyOn(api, 'GET').mockResolvedValue({ data: { agents: [] } } as never)
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
    expect(result.current.data?.edges).toHaveLength(3)
    // Live badges flow through from the AgentNode projection (AAASM-5036).
    expect(result.current.data?.nodes[0].mode).toBe('shadow')
    expect(result.current.data?.nodes[0].flagged).toBe(true)
    // Widened projection (AAASM-5099): non-structural kinds, the cross-team
    // flag, and the policy-inheritance chain all survive the hook.
    expect(result.current.data?.edges.map((e) => e.kind)).toEqual(['delegation', 'reads', 'approves'])
    expect(result.current.data?.edges[0].crossTeam).toBe(true)
    expect(result.current.data?.edges[2].crossTeam).toBe(false)
    expect(result.current.data?.nodes[0].effectivePermissions?.chain).toHaveLength(2)
    expect(result.current.data?.nodes[0].effectivePermissions?.deny).toEqual(['terminal_exec'])
    // A node without the field folds to null, not an empty chain.
    expect(result.current.data?.nodes[1].effectivePermissions).toBeNull()
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

  /**
   * AAASM-5136. ADR-0017 item 3 ratified a 5s poll and recorded it as *shipped*;
   * its own AAASM-5082 correction established that nothing in `dashboard/src`
   * set `refetchInterval` at all, so the graph was frozen between mounts. A
   * suspend performed elsewhere never reached the operator.
   *
   * The timer is driven rather than the option inspected: reading the config
   * back would only prove the value was passed, not that a second fetch ever
   * happens.
   */
  it('re-fetches on the ratified 5s interval', async () => {
    vi.useFakeTimers()
    try {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(JSON.stringify(API_GRAPH), { status: 200 }),
      )
      const { result } = renderHook(() => useTopologyQuery(), { wrapper })

      await vi.waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(fetchSpy).toHaveBeenCalledTimes(1)

      await vi.advanceTimersByTimeAsync(5_000)
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(2))

      await vi.advanceTimersByTimeAsync(5_000)
      await vi.waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(3))
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not re-fetch before the interval elapses', async () => {
    // Guards the cadence itself: a much shorter interval would hammer the
    // gateway, and `staleTime` alone (which schedules nothing) would leave the
    // count at 1 forever — the exact bug this replaces.
    vi.useFakeTimers()
    try {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response(JSON.stringify(API_GRAPH), { status: 200 }),
      )
      const { result } = renderHook(() => useTopologyQuery(), { wrapper })

      await vi.waitFor(() => expect(result.current.isSuccess).toBe(true))
      await vi.advanceTimersByTimeAsync(4_000)
      expect(fetchSpy).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('returns an empty graph shape without crashing', async () => {
    const empty: components['schemas']['TopologyGraphResponse'] = { nodes: [], edges: [], unclaimed_observable: true }
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
