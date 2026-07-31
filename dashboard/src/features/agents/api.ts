import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import type { AgentEnforcementLookup, AgentTrustLookup } from './fleetTypes'

export type Agent = components['schemas']['AgentResponse']
export type LogEntry = components['schemas']['LogEntry']
export type SubtreeBurn = components['schemas']['SubtreeBurnResponse']
export type DailyBurnPoint = components['schemas']['DailyBurnPointResponse']
export type ChildSpend = components['schemas']['ChildSpendResponse']
export type BurnPeriod = '7d' | '30d'
export type EffectivePermissions = components['schemas']['EffectivePermissionsResponse']
export type PermissionSource = components['schemas']['PermissionSourceResponse']
export type FleetActiveSession = components['schemas']['FleetActiveSessionResponse']
export type AgentDecision = components['schemas']['AgentDecisionResponse']
export type AgentDecisions = components['schemas']['AgentDecisionsResponse']

export function useAgentsQuery() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch agents')
      // AAASM-4892: /agents and /logs return a paginated { items, total } object.
      return data?.items ?? []
    },
  })
}

/** Window presets accepted by `GET /api/v1/analytics/agent-enforcement`. */
export type EnforcementWindow = '1h' | '24h' | '7d' | '30d'

/**
 * Per-agent blocked + scrubbed counts for the Fleet columns and Agent-Detail
 * tiles (AAASM-5084). Folds the endpoint's array into a lookup keyed by agent
 * id so callers can join it onto fleet rows in O(1); agents with no
 * blocked/scrubbed decisions in the window are simply absent (rendered as `—`).
 */
export function useAgentEnforcementQuery(window: EnforcementWindow = '24h') {
  return useQuery<AgentEnforcementLookup>({
    queryKey: ['analytics', 'agent-enforcement', window],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/analytics/agent-enforcement', {
        params: { query: { window } },
      })
      if (error) throw new Error('Failed to fetch agent enforcement metrics')
      // `agent_id` is raw wire input, so a plain object accumulator would let a
      // value of `constructor`/`__proto__`/etc. write through to (or read back)
      // an inherited prototype member instead of being stored as an ordinary
      // entry. A Map treats every key as an ordinary key.
      const lookup = new Map<string, { blocked: number; scrubbed: number }>()
      for (const row of data ?? []) {
        lookup.set(row.agent_id, { blocked: row.blocked, scrubbed: row.scrubbed })
      }
      return lookup
    },
  })
}

/** Full `GET /api/v1/analytics/trust` response — carries the echoed weight-set. */
export type TrustResponse = components['schemas']['TrustResponse']

/**
 * Per-agent behavioural trust scores for the Fleet TrustBar, Topology badge and
 * Agent-Detail gauge (AAASM-5083, ADR 0019). Folds the response's `agents` array
 * into a lookup keyed by agent id so callers join it onto their rows in O(1).
 *
 * The endpoint reports a cold-start agent (`< minActions` governed actions in
 * the window) as an explicit `trust: null`, which is kept as `null` here — the
 * consumer renders `—`, never `0`. When the audit window is truncated the
 * endpoint emits no scores at all (`agents` empty), so every agent falls through
 * as an absent key, again rendered `—` (ADR 0019 Guardrail 2). The score is
 * comparable only under the tenant's echoed `weights`, surfaced in the UI as the
 * "under your configured weights" framing (Guardrail 1).
 *
 * A Map, not a plain object: `agent_id` is raw wire input, so a value of
 * `constructor`/`__proto__`/etc. must be an ordinary key rather than hitting the
 * prototype setter (AAASM-5237).
 */
export function useTrustQuery() {
  return useQuery<AgentTrustLookup>({
    queryKey: ['analytics', 'trust'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/analytics/trust')
      if (error) throw new Error('Failed to fetch trust scores')
      const lookup = new Map<string, number | null>()
      for (const row of data?.agents ?? []) {
        lookup.set(row.agent_id, row.trust)
      }
      return lookup
    },
  })
}

export function useActiveSessionsQuery() {
  return useQuery<FleetActiveSession[]>({
    queryKey: ['fleet', 'active-sessions'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/fleet/active-sessions')
      if (error) throw new Error('Failed to fetch active sessions')
      return data ?? []
    },
  })
}

export function useAgentQuery(id: string) {
  return useQuery({
    queryKey: ['agents', id],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}', {
        params: { path: { id } },
      })
      if (error) throw new Error('Failed to fetch agent')
      return data
    },
    enabled: !!id,
  })
}

export function useAgentSubtreeBurnQuery(id: string, period: BurnPeriod = '7d') {
  return useQuery<SubtreeBurn>({
    queryKey: ['agents', id, 'subtree-burn', period],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}/subtree-burn', {
        params: { path: { id }, query: { period } },
      })
      if (error) throw new Error('Failed to fetch subtree burn')
      if (!data) throw new Error('Subtree burn response was empty')
      return data
    },
    enabled: !!id,
  })
}

export function useAgentCapabilitiesQuery(id: string) {
  return useQuery<EffectivePermissions>({
    queryKey: ['agents', id, 'capabilities'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}/capabilities', {
        params: { path: { id } },
      })
      if (error) throw new Error('Failed to fetch agent capabilities')
      if (!data) throw new Error('Agent capabilities response was empty')
      return data
    },
    enabled: !!id,
  })
}

/**
 * Recent per-agent decision stream for the agent-detail Traffic tab (AAASM-5058).
 *
 * Reads `GET /api/v1/agents/{id}/decisions` — a read-only projection of the
 * gateway's audit log, newest-first, one row per governance decision. The
 * `latencyMs` column is always `null` today (no per-decision latency is
 * recorded); the UI renders it as `—` rather than a fabricated number.
 */
export function useAgentDecisionsQuery(id: string, limit = 50) {
  return useQuery<AgentDecision[]>({
    queryKey: ['agents', id, 'decisions', limit],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents/{id}/decisions', {
        params: { path: { id }, query: { limit } },
      })
      if (error) throw new Error('Failed to fetch agent decisions')
      return data?.decisions ?? []
    },
    enabled: !!id,
  })
}

export function useAgentEventsQuery(id: string) {
  return useQuery({
    queryKey: ['agents', id, 'events'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/logs', {
        params: { query: { agent_id: id, per_page: 50 } },
      })
      if (error) throw new Error('Failed to fetch agent events')
      // AAASM-4892: /agents and /logs return a paginated { items, total } object.
      return data?.items ?? []
    },
    enabled: !!id,
  })
}
