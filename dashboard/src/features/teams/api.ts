import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
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

export interface TeamListRow {
  team_id: string
  agent_count: number
  root_agent_count: number
  daily_spend_usd: number | null
  daily_limit_usd: number | null
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
  return overview.teams.map((team): TeamListRow => {
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
      void client.invalidateQueries({ queryKey: ['topology', 'team', teamId] })
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
      void client.invalidateQueries({ queryKey: ['topology', 'team', teamId] })
    },
  })
}
