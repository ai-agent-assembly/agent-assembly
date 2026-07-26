/**
 * Data-layer guard for AAASM-5110.
 *
 * The defect was not that the projections were wrong — there were no
 * projections. Four agents and a grant table were constants, and the hooks
 * resolved them without touching the network. These tests therefore assert two
 * separate things: that the hooks *do* call the real endpoints, and that every
 * field those endpoints do not carry arrives as a `Certain` absence rather than
 * a value.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { isKnown } from '../../lib/truthfulness'
import {
  agentStatusVariant,
  toPermissionCascade,
  toRegistryAgent,
  useAgentPermissionsQuery,
  useAgentsQuery,
} from './agents'

interface FetchResult {
  data?: unknown
  error?: unknown
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>
  }
}

/**
 * A registry entry with every field the endpoint actually populates.
 *
 * `status` is the Rust `Debug` rendering `aa-api` emits
 * (`format!("{:?}", r.status)`), not a lowercase enum — a fixture using
 * `'active'` describes a response the gateway cannot produce.
 */
function rawAgent(over: Record<string, unknown> = {}) {
  return {
    id: 'a1',
    name: 'orchestrator',
    framework: 'langgraph',
    version: '1.0.0',
    status: 'Active',
    tool_names: [],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
    last_event: '2026-07-26T09:00:00Z',
    ...over,
  }
}

let get: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('agentStatusVariant', () => {
  // The wire values are `format!("{:?}", aa_gateway::registry::AgentStatus)`.
  it.each([
    ['Active', 'Active'],
    ['Deregistered', 'Deregistered'],
    ['Suspended(Manual)', 'Suspended'],
    ['Suspended(BudgetExceeded)', 'Suspended'],
    ['Suspended(ParentDeregistered)', 'Suspended'],
    ['Suspended(ParentSuspended { parent_agent_id: [1, 2, 3] })', 'Suspended'],
  ])('reads the outer variant of %s as %s', (wire, expected) => {
    expect(agentStatusVariant(wire)).toBe(expected)
  })

  it('passes through a value it does not recognise', () => {
    // Classification must never rewrite the status; an unknown variant keeps
    // its own name so the caller can still render it verbatim.
    expect(agentStatusVariant('SomethingNew')).toBe('SomethingNew')
  })
})

describe('toRegistryAgent', () => {
  it('carries id, name and the registry status verbatim', () => {
    const agent = toRegistryAgent(rawAgent() as never)
    expect(agent.id).toBe('a1')
    expect(agent.name).toBe('orchestrator')
    expect(agent.status).toEqual({ known: true, value: 'Active' })
  })

  it('keeps a suspension payload intact', () => {
    // `BudgetExceeded` (auto-resumable) and `Manual` (operator-only) are
    // operationally different, so the payload must survive the projection.
    const agent = toRegistryAgent(rawAgent({ status: 'Suspended(BudgetExceeded)' }) as never)
    expect(agent.status).toEqual({ known: true, value: 'Suspended(BudgetExceeded)' })
  })

  it('does not coerce an unrecognised status into a known variant', () => {
    // The schema types `status` as an open string. Whatever the gateway says is
    // what renders — mapping it onto the nearest known word would assert a
    // liveness state the gateway never reported.
    const agent = toRegistryAgent(rawAgent({ status: 'Quarantined' }) as never)
    expect(agent.status).toEqual({ known: true, value: 'Quarantined' })
  })

  it('reports the owning team as not-supported, never as a team name', () => {
    const agent = toRegistryAgent(rawAgent() as never)
    expect(isKnown(agent.owner_team)).toBe(false)
    expect(agent.owner_team).toMatchObject({ known: false, state: 'not-supported' })
  })

  it('keeps owner_team not-supported even when metadata carries a team-shaped key', () => {
    // The regression this blocks: reaching into the free-form metadata bag for
    // something that looks like a team is how an invented owner column comes
    // back. `AgentResponse` has no owning-team field; metadata is not one.
    const agent = toRegistryAgent(rawAgent({ metadata: { team: 'platform' } }) as never)
    expect(agent.owner_team).toMatchObject({ known: false, state: 'not-supported' })
  })

  it('maps last_event onto last_seen when the registry has one', () => {
    const agent = toRegistryAgent(rawAgent() as never)
    expect(agent.last_seen).toEqual({ known: true, value: '2026-07-26T09:00:00Z' })
  })

  it.each([null, undefined, ''])('reports last_seen as unknown for %p', (value) => {
    const agent = toRegistryAgent(rawAgent({ last_event: value }) as never)
    expect(agent.last_seen).toMatchObject({ known: false, state: 'unknown' })
  })

  it('reports an empty status as unknown rather than an empty chip', () => {
    const agent = toRegistryAgent(rawAgent({ status: '' }) as never)
    expect(agent.status).toMatchObject({ known: false, state: 'unknown' })
  })
})

describe('useAgentsQuery', () => {
  it('reads the real registry endpoint and projects its items', async () => {
    get.mockResolvedValue({
      data: { items: [rawAgent()], page: 1, per_page: 100, total: 1 },
    } satisfies FetchResult)

    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(get).toHaveBeenCalledWith('/api/v1/agents', {
      params: { query: { per_page: 100 } },
    })
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].name).toBe('orchestrator')
  })

  it('surfaces a transport failure as an error rather than an empty roster', async () => {
    // An empty roster is a claim ("no agents are registered"); a failed request
    // supports no claim at all, so it must not resolve to one.
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.data).toBeUndefined()
  })

  it('treats a body-less 200 as an empty roster', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentsQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([])
  })
})

describe('toPermissionCascade', () => {
  it('preserves the per-scope contributions as cascade evidence', () => {
    const cascade = toPermissionCascade('a1', {
      allow: ['tools.invoke'],
      deny: ['secrets.read'],
      sources: [
        { scope: 'global', allow: ['tools.invoke'], deny: [] },
        { scope: 'team:platform', allow: [], deny: ['secrets.read'] },
      ],
    } as never)

    expect(cascade.agentId).toBe('a1')
    expect(cascade.sources.map((s) => s.scope)).toEqual(['global', 'team:platform'])
    expect(cascade.sources[1].deny).toEqual(['secrets.read'])
  })

  it('preserves the merged verdict the backend already computed', () => {
    // `effective_permissions` merges the cascade most-restrictive-wins before
    // it ever reaches the client. Dropping `allow`/`deny` here would leave the
    // panel re-deriving an answer the endpoint had already given it.
    const cascade = toPermissionCascade('a1', {
      allow: [],
      deny: ['secrets.read'],
      sources: [
        { scope: 'global', allow: ['secrets.read'], deny: [] },
        { scope: 'team:platform', allow: [], deny: ['secrets.read'] },
      ],
    } as never)

    expect(cascade.allow).toEqual([])
    expect(cascade.deny).toEqual(['secrets.read'])
  })

  it('keeps an empty cascade empty instead of inventing a scope for it', () => {
    const cascade = toPermissionCascade('a1', { allow: [], deny: [], sources: [] } as never)
    expect(cascade.sources).toEqual([])
  })
})

describe('useAgentPermissionsQuery', () => {
  it('reads the real capabilities endpoint for the selected agent', async () => {
    get.mockResolvedValue({
      data: { allow: [], deny: [], sources: [{ scope: 'global', allow: ['a'], deny: [] }] },
    } satisfies FetchResult)

    const { result } = renderHook(() => useAgentPermissionsQuery('a1'), {
      wrapper: makeWrapper(),
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))

    expect(get).toHaveBeenCalledWith('/api/v1/agents/{id}/capabilities', {
      params: { path: { id: 'a1' } },
    })
    expect(result.current.data?.sources).toHaveLength(1)
  })

  it('issues no request while no agent is selected', async () => {
    const { result } = renderHook(() => useAgentPermissionsQuery(null), {
      wrapper: makeWrapper(),
    })
    await waitFor(() => expect(result.current.fetchStatus).toBe('idle'))
    expect(get).not.toHaveBeenCalled()
  })

  it('fails rather than resolving to an empty cascade when the body is missing', async () => {
    // An empty cascade is the AAASM-5106 signal the panel renders as
    // "unconfigured". A missing body cannot support that signal, so it must not
    // be allowed to impersonate one.
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    const { result } = renderHook(() => useAgentPermissionsQuery('a1'), {
      wrapper: makeWrapper(),
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })

  it('fails on a transport error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { result } = renderHook(() => useAgentPermissionsQuery('a1'), {
      wrapper: makeWrapper(),
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })
})
