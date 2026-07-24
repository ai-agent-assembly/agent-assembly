import { useQuery } from '@tanstack/react-query'
import { analyticsFetch } from './analyticsFetch'
import { encodeFilters, type PresetRange, type FilterParams } from './urlState'
import type { ToolUsageResponse } from './useToolUsageQuery'
import type { ActionVolumeResponse } from './useActionVolumeQuery'
import type { ToolStat } from './toolUsageUtils'

/**
 * Per-agent traffic summary for the agent-detail Traffic tab (AAASM-5041).
 *
 * Assembled from the two existing fleet analytics endpoints, both scoped to a
 * single agent via the shared `agents` filter param that
 * `/api/v1/analytics/*` already accepts:
 *   - `tool-usage`     → per-tool call counts + error rates
 *   - `action-volume`  → time series, summed to a single 24h action total
 *
 * NOTE: this is the aggregate view. The design's per-decision recent-traffic
 * stream (ts / verb / resource / decision / latency / policy per row) has no
 * per-agent endpoint today — that live decision stream lives fleet-wide on the
 * Live Ops / trace surfaces, so it is intentionally out of scope here.
 */
export interface AgentTraffic {
  /** Per-tool call volume + error rate, most-called first is left to the view. */
  readonly tools: readonly ToolStat[]
  /** Total actions across the window (sum of every action-volume series point). */
  readonly totalActions: number
}

function sumActions(res: ActionVolumeResponse): number {
  return res.series.reduce(
    (seriesTotal, series) =>
      seriesTotal + series.points.reduce((pointTotal, p) => pointTotal + p.value, 0),
    0,
  )
}

export function useAgentTrafficQuery(agentId: string, range: PresetRange = '24h') {
  return useQuery({
    queryKey: ['analytics', 'agent-traffic', agentId, range],
    enabled: !!agentId,
    queryFn: async (): Promise<AgentTraffic> => {
      const filters: FilterParams = { range, agents: [agentId], teams: [] }
      const params = encodeFilters(filters).toString()
      const [toolUsage, actionVolume] = await Promise.all([
        analyticsFetch<ToolUsageResponse>(`/api/v1/analytics/tool-usage?${params}`),
        analyticsFetch<ActionVolumeResponse>(`/api/v1/analytics/action-volume?${params}`),
      ])
      return { tools: toolUsage.tools, totalActions: sumActions(actionVolume) }
    },
  })
}
