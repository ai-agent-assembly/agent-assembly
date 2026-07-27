import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { ignorePromise } from '../../lib/ignorePromise'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

export type TopologyOverview = components['schemas']['TopologyOverview']
export type TeamSummary = components['schemas']['TeamSummary']
export type TeamCostEntry = components['schemas']['TeamCostEntry']
export type CostSummary = components['schemas']['CostSummary']
export type TeamTopology = components['schemas']['TeamTopology']
export type AgentLineage = components['schemas']['AgentLineage']
export type LineageStep = components['schemas']['LineageStep']
export type AgentNode = components['schemas']['AgentNode']
export type TeamPolicy = components['schemas']['TeamPolicyResponse']

export interface TeamListRow {
  team_id: string
  agent_count: number
  root_agent_count: number
  daily_spend_usd: number | null
  daily_limit_usd: number | null
  /**
   * Month-to-date spend for the team in USD, or `null` when none is on the wire
   * (AAASM-5160).
   *
   * `TeamCostEntry.monthly_spend_usd` is optional: the gateway only accumulates
   * a monthly figure once monthly tracking is enabled, and a team absent from
   * the cost breakdown has none at all. There is deliberately no companion
   * limit — `TeamCostEntry` carries no ceiling of any window, and a team-tier
   * monthly one is sign-off-gated on ADR-0020 / AAASM-5087.
   */
  monthly_spend_usd: number | null
  burn_pct: number | null
}

export function useTopologyOverviewQuery() {
  return useQuery({
    queryKey: ['topology', 'overview'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/topology/overview')
      if (error) throw new Error('Failed to fetch topology overview')
      return data as TopologyOverview
    },
  })
}

/**
 * Every agent the caller's tenant may see, as `AgentNode` records
 * (`GET /api/v1/topology`, AAASM-5040) — no depth, status, or team filter.
 *
 * The Teams page needs the whole fleet, not `/topology/overview`'s
 * `standalone_root_agents`, to answer "which agents does no team govern?"
 * (AAASM-5157). The overview's field is root-only, so a spawned agent with no
 * team fell out of every grouping on the page.
 *
 * Deliberately not `features/topology`'s `useTopologyQuery`, which fetches the
 * same endpoint: that hook maps the response onto the graph view model, which
 * drops `depth` and folds any unrecognised `status` to `idle`. The orphan rows
 * render both verbatim, and a governance list is the wrong place to show a
 * lossy projection of an agent's real state.
 */
export function useTopologyAgentsQuery() {
  return useQuery({
    queryKey: ['topology', 'agents'],
    // Matches `features/topology`'s hook over the same endpoint. This is the
    // most expensive topology handler — it resolves a policy cascade and
    // effective permissions per node plus a budget snapshot, and pages the edge
    // set, nearly all of which this page discards — so it must not refetch on
    // every mount and window focus. It also narrows the window in which this
    // page holds two snapshots taken at different moments (see `TeamsPage`).
    // The two hooks cannot share a cache entry: distinct keys are never deduped,
    // and prefix matching applies to invalidation only.
    staleTime: 5_000,
    queryFn: async (): Promise<AgentNode[]> => {
      const { data, error } = await api.GET('/api/v1/topology')
      if (error) throw new Error('Failed to fetch topology agents')
      if (!data) throw new Error('Topology response was empty')
      return data.nodes
    },
  })
}

export function useCostSummaryQuery() {
  return useQuery({
    queryKey: ['costs', 'summary'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/costs')
      if (error) throw new Error('Failed to fetch cost summary')
      return data as CostSummary
    },
  })
}

/**
 * Policies in force for one team (`GET /api/v1/policies/team/{team_id}`,
 * AAASM-5096) — the union of the team's agents' policy cascades, deduplicated
 * by document. Backs the Active-policies card.
 *
 * Kept separate from `GET /api/v1/policies`, which requires Admin scope because
 * it discloses raw policy YAML; this one is readable by the team's own operator.
 *
 * Resolves to `null` — not `[]` — when the API reports the mapping as
 * unresolvable. The two are different governance claims and the `?? []` that
 * would flatten them is exactly the bug: `[]` renders as "no policy is in force
 * for this team", which is false while the engine's primary policy slot is
 * enforcing over the team's agents (AAASM-5106).
 */
export function useTeamPoliciesQuery(teamId: string | undefined) {
  return useQuery({
    queryKey: ['policies', 'team', teamId],
    enabled: !!teamId,
    queryFn: async (): Promise<TeamPolicy[] | null> => {
      const { data, error } = await api.GET('/api/v1/policies/team/{team_id}', {
        params: { path: { team_id: teamId! } },
      })
      if (error) throw new Error('Failed to fetch team policies')
      return data?.policies ?? null
    },
  })
}

export interface TeamTopologyResult {
  data: TeamTopology | undefined
  notFound: boolean
  isLoading: boolean
  isError: boolean
}

export function useTeamTopologyQuery(teamId: string | undefined): TeamTopologyResult {
  const query = useQuery({
    queryKey: ['topology', 'team', teamId],
    enabled: !!teamId,
    retry: false,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/topology/team/{team_id}', {
        params: { path: { team_id: teamId! } },
      })
      if (response?.status === 404) {
        const err = new Error('Team not found') as Error & { notFound?: boolean }
        err.notFound = true
        throw err
      }
      if (error) throw new Error('Failed to fetch team topology')
      return data as TeamTopology
    },
  })
  const notFound = !!(query.error && (query.error as Error & { notFound?: boolean }).notFound)
  return {
    data: query.data,
    notFound,
    isLoading: query.isLoading,
    isError: query.isError && !notFound,
  }
}

export function useAgentLineageQuery(agentId: string | undefined) {
  return useQuery({
    queryKey: ['topology', 'lineage', agentId],
    enabled: !!agentId,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/topology/lineage/{agent_id}', {
        params: { path: { agent_id: agentId! } },
      })
      if (error) throw new Error('Failed to fetch agent lineage')
      return data as AgentLineage
    },
  })
}

function parseUsd(value: string | null | undefined): number | null {
  if (value == null) return null
  const n = Number.parseFloat(value)
  return Number.isFinite(n) ? n : null
}

export function joinTeamRows(overview: TopologyOverview | undefined, costs: CostSummary | undefined): TeamListRow[] {
  if (!overview) return []
  const dailyLimit = parseUsd(costs?.daily_limit_usd)
  const costByTeam = new Map<string, TeamCostEntry>()
  for (const entry of costs?.per_team ?? []) costByTeam.set(entry.team_id, entry)
  return (overview?.teams ?? []).map((team): TeamListRow => {
    const cost = costByTeam.get(team.team_id)
    const dailySpend = parseUsd(cost?.daily_spend_usd)
    const burnPct = dailySpend != null && dailyLimit != null && dailyLimit > 0
      ? (dailySpend / dailyLimit) * 100
      : null
    return {
      team_id: team.team_id,
      agent_count: team.agent_count,
      root_agent_count: team.root_agent_count,
      daily_spend_usd: dailySpend,
      daily_limit_usd: dailyLimit,
      monthly_spend_usd: parseUsd(cost?.monthly_spend_usd),
      burn_pct: burnPct,
    }
  })
}

export function teamCostFor(teamId: string, costs: CostSummary | undefined): TeamCostEntry | undefined {
  return costs?.per_team?.find(entry => entry.team_id === teamId)
}

async function suspendAgent(agentId: string, reason: string): Promise<void> {
  const { error } = await api.POST('/api/v1/agents/{id}/suspend', {
    params: { path: { id: agentId } },
    body: { reason },
  })
  if (error) throw new Error(`Failed to suspend agent ${agentId}`)
}

async function resumeAgent(agentId: string): Promise<void> {
  const { error } = await api.POST('/api/v1/agents/{id}/resume', {
    params: { path: { id: agentId } },
  })
  if (error) throw new Error(`Failed to resume agent ${agentId}`)
}

function applyMemberStatus(client: QueryClient, teamId: string, status: 'active' | 'suspended') {
  const key = ['topology', 'team', teamId]
  const previous = client.getQueryData<TeamTopology>(key)
  if (!previous) return previous
  client.setQueryData<TeamTopology>(key, {
    ...previous,
    members: previous.members.map(m => ({ ...m, status })),
  })
  return previous
}

export interface TeamActionVariables {
  teamId: string
  memberIds: string[]
}

export function useSuspendTeam() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: async ({ memberIds }: TeamActionVariables) => {
      await Promise.all(memberIds.map(id => suspendAgent(id, 'team-level suspend')))
    },
    onMutate: ({ teamId }) => ({ previous: applyMemberStatus(client, teamId, 'suspended') }),
    onError: (_err, { teamId }, context) => {
      if (context?.previous) client.setQueryData(['topology', 'team', teamId], context.previous)
    },
    onSettled: (_data, _err, { teamId }) => {
      ignorePromise(client.invalidateQueries({ queryKey: ['topology', 'team', teamId] }))
    },
  })
}

export function useResumeTeam() {
  const client = useQueryClient()
  return useMutation({
    mutationFn: async ({ memberIds }: TeamActionVariables) => {
      await Promise.all(memberIds.map(resumeAgent))
    },
    onMutate: ({ teamId }) => ({ previous: applyMemberStatus(client, teamId, 'active') }),
    onError: (_err, { teamId }, context) => {
      if (context?.previous) client.setQueryData(['topology', 'team', teamId], context.previous)
    },
    onSettled: (_data, _err, { teamId }) => {
      ignorePromise(client.invalidateQueries({ queryKey: ['topology', 'team', teamId] }))
    },
  })
}
