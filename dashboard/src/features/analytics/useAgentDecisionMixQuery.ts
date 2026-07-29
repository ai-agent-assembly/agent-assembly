import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'

/**
 * Per-agent decision distribution for the Agent-Detail traffic-mix bar
 * (AAASM-5085), backing `GET /api/v1/analytics/agent-decision-mix`.
 *
 * The endpoint returns a fleet-wide array (one row per agent that recorded a
 * tracked decision in the window), so the hook folds it into a lookup keyed by
 * agent id and returns the single requested agent's row — or `null` when that
 * agent has no tracked decision in the window. `null` is the honest empty
 * signal the view renders as "no decisions in this window", distinct from a row
 * of all-zeros (which the endpoint never emits: an agent with nothing to report
 * is simply absent).
 */
export type AgentDecisionMix = components['schemas']['AgentDecisionMixCounts']

/** Window presets accepted by `GET /api/v1/analytics/agent-decision-mix`. */
export type DecisionMixWindow = '1h' | '24h' | '7d' | '30d'

export function useAgentDecisionMixQuery(agentId: string, window: DecisionMixWindow = '24h') {
  return useQuery<AgentDecisionMix | null>({
    queryKey: ['analytics', 'agent-decision-mix', agentId, window],
    enabled: !!agentId,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/analytics/agent-decision-mix', {
        params: { query: { window } },
      })
      if (error) throw new Error('Failed to fetch agent decision mix')
      // Find this agent's row. The endpoint omits agents with no tracked
      // decision, so a miss is a truthful "no data", returned as null.
      return (data ?? []).find((row) => row.agent_id === agentId) ?? null
    },
  })
}
