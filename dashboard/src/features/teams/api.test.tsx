import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  joinTeamRows,
  teamCostFor,
  useAgentLineageQuery,
  useCostSummaryQuery,
  useSuspendTeam,
  useResumeTeam,
  useTeamTopologyQuery,
  useTopologyOverviewQuery,
  type CostSummary,
  type TopologyOverview,
} from './api'

interface FetchResult {
  data?: unknown
  error?: unknown
  response?: { status: number }
}

function makeWrapper() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return { client, wrapper }
}

const MOCK_OVERVIEW: TopologyOverview = {
  teams: [
    { team_id: 'research', agent_count: 4, root_agent_count: 1 },
    { team_id: 'support', agent_count: 2, root_agent_count: 1 },
  ],
} as unknown as TopologyOverview

const MOCK_COSTS: CostSummary = {
  daily_limit_usd: '100.00',
  per_team: [
    { team_id: 'research', daily_spend_usd: '25.00' },
    { team_id: 'support', daily_spend_usd: 'not-a-number' },
  ],
} as unknown as CostSummary

let get: Mock
let post: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useTopologyOverviewQuery', () => {
  it('returns the overview payload on success', async () => {
    get.mockResolvedValue({ data: MOCK_OVERVIEW } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTopologyOverviewQuery(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.teams).toHaveLength(2)
    expect(get).toHaveBeenCalledWith('/api/v1/topology/overview')
  })

  it('throws a descriptive error on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTopologyOverviewQuery(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch topology overview')
  })
})

describe('useCostSummaryQuery', () => {
  it('returns the cost summary on success', async () => {
    get.mockResolvedValue({ data: MOCK_COSTS } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useCostSummaryQuery(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.daily_limit_usd).toBe('100.00')
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useCostSummaryQuery(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch cost summary')
  })
})

describe('useTeamTopologyQuery', () => {
  it('stays disabled and does not fetch when teamId is undefined', () => {
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTeamTopologyQuery(undefined), { wrapper })
    expect(result.current.isLoading).toBe(false)
    expect(get).not.toHaveBeenCalled()
  })

  it('returns the team topology on success', async () => {
    get.mockResolvedValue({ data: { team_id: 'research', members: [] } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTeamTopologyQuery('research'), { wrapper })
    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(result.current.notFound).toBe(false)
    expect(result.current.isError).toBe(false)
    expect(get).toHaveBeenCalledWith('/api/v1/topology/team/{team_id}', {
      params: { path: { team_id: 'research' } },
    })
  })

  it('surfaces notFound (not isError) on a 404 response', async () => {
    get.mockResolvedValue({ response: { status: 404 } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTeamTopologyQuery('ghost'), { wrapper })
    await waitFor(() => expect(result.current.notFound).toBe(true))
    expect(result.current.isError).toBe(false)
  })

  it('surfaces isError on a non-404 failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' }, response: { status: 500 } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useTeamTopologyQuery('research'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.notFound).toBe(false)
  })
})

describe('useAgentLineageQuery', () => {
  it('is disabled when agentId is undefined', () => {
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useAgentLineageQuery(undefined), { wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(get).not.toHaveBeenCalled()
  })

  it('returns the lineage on success', async () => {
    const lineage = { agent_id: 'a1', steps: [] }
    get.mockResolvedValue({ data: lineage } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useAgentLineageQuery('a1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(lineage)
  })

  it('throws on failure', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useAgentLineageQuery('a1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch agent lineage')
  })
})

describe('joinTeamRows', () => {
  it('returns an empty list when overview is undefined', () => {
    expect(joinTeamRows(undefined, MOCK_COSTS)).toEqual([])
  })

  it('returns an empty list when overview is missing the teams field', () => {
    // A 200 response with a partial object (no `teams` array) must not throw.
    expect(joinTeamRows({} as TopologyOverview, MOCK_COSTS)).toEqual([])
  })

  it('joins overview rows with parsed cost data and computes burn percentage', () => {
    const rows = joinTeamRows(MOCK_OVERVIEW, MOCK_COSTS)
    expect(rows).toHaveLength(2)
    const research = rows.find(r => r.team_id === 'research')!
    expect(research.daily_spend_usd).toBe(25)
    expect(research.daily_limit_usd).toBe(100)
    expect(research.burn_pct).toBe(25)
  })

  it('treats an unparseable spend as null and yields a null burn', () => {
    const support = joinTeamRows(MOCK_OVERVIEW, MOCK_COSTS).find(r => r.team_id === 'support')!
    expect(support.daily_spend_usd).toBeNull()
    expect(support.burn_pct).toBeNull()
  })

  it('yields a null burn when there is no cost data at all', () => {
    const rows = joinTeamRows(MOCK_OVERVIEW, undefined)
    expect(rows[0].daily_limit_usd).toBeNull()
    expect(rows[0].daily_spend_usd).toBeNull()
    expect(rows[0].burn_pct).toBeNull()
  })
})

describe('teamCostFor', () => {
  it('finds the matching per-team cost entry', () => {
    expect(teamCostFor('research', MOCK_COSTS)?.team_id).toBe('research')
  })

  it('returns undefined when costs are absent', () => {
    expect(teamCostFor('research', undefined)).toBeUndefined()
  })
})

describe('useSuspendTeam', () => {
  it('suspends every member id and resolves', async () => {
    post.mockResolvedValue({ error: undefined } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useSuspendTeam(), { wrapper })
    await result.current.mutateAsync({ teamId: 'research', memberIds: ['a1', 'a2'] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledTimes(2)
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/suspend', {
      params: { path: { id: 'a1' } },
      body: { reason: 'team-level suspend' },
    })
  })

  it('applies an optimistic suspended status then rolls back on failure', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { client, wrapper } = makeWrapper()
    client.setQueryData(['topology', 'team', 'research'], {
      team_id: 'research',
      members: [{ id: 'a1', status: 'active' }],
    })
    const { result } = renderHook(() => useSuspendTeam(), { wrapper })
    await expect(
      result.current.mutateAsync({ teamId: 'research', memberIds: ['a1'] }),
    ).rejects.toThrow()
    await waitFor(() => {
      const restored = client.getQueryData<{ members: { status: string }[] }>([
        'topology',
        'team',
        'research',
      ])
      expect(restored?.members[0].status).toBe('active')
    })
  })
})

describe('useResumeTeam', () => {
  it('resumes every member id and resolves', async () => {
    post.mockResolvedValue({ error: undefined } satisfies FetchResult)
    const { client, wrapper } = makeWrapper()
    client.setQueryData(['topology', 'team', 'research'], {
      team_id: 'research',
      members: [{ id: 'a1', status: 'suspended' }],
    })
    const { result } = renderHook(() => useResumeTeam(), { wrapper })
    await result.current.mutateAsync({ teamId: 'research', memberIds: ['a1'] })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(post).toHaveBeenCalledWith('/api/v1/agents/{id}/resume', {
      params: { path: { id: 'a1' } },
    })
  })

  it('throws when a resume call fails', async () => {
    post.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    const { wrapper } = makeWrapper()
    const { result } = renderHook(() => useResumeTeam(), { wrapper })
    await expect(
      result.current.mutateAsync({ teamId: 'research', memberIds: ['a1'] }),
    ).rejects.toThrow('Failed to resume agent a1')
  })
})
