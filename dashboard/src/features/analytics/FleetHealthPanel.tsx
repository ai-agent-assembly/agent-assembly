import { useMemo } from 'react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useFleetHealthQuery } from './useFleetHealthQuery'
import { CHART_CATEGORICAL_PALETTE } from './chartPalette'
import type { AgentHealth } from './useFleetHealthQuery'

const SPARKLINE_COLOR = CHART_CATEGORICAL_PALETTE[0]

function currentScore(agent: AgentHealth): number {
  if (agent.points.length === 0) return 0
  return agent.points[agent.points.length - 1].score
}

function scoreBadgeClass(score: number): string {
  if (score >= 90) return 'fleet-health-panel__badge--green'
  if (score >= 70) return 'fleet-health-panel__badge--amber'
  return 'fleet-health-panel__badge--red'
}

export function FleetHealthPanel() {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = useFleetHealthQuery(filters)

  const rawAgents = data?.agents
  const agents = useMemo(() => rawAgents ?? [], [rawAgents])

  return (
    <div className="fleet-health-panel" data-testid="fleet-health-panel">
      <div className="fleet-health-panel__header">
        <h2 className="fleet-health-panel__title">Fleet Health</h2>
      </div>

      {isPending ? (
        <div className="fleet-health-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="fleet-health-panel__error">Failed to load fleet health data.</p>
      ) : agents.length === 0 ? (
        <div className="fleet-health-panel__empty">
          <p>No agents reporting in this window.</p>
        </div>
      ) : (
        <ul className="fleet-health-panel__list" aria-label="Agent health">
          {agents.map(agent => {
            const score = currentScore(agent)
            return (
              <li
                key={agent.id}
                className="fleet-health-panel__row"
                data-testid={`fleet-health-row-${agent.id}`}
              >
                <span className="fleet-health-panel__name" title={agent.name}>
                  {agent.name}
                </span>
                <span className="fleet-health-panel__sparkline" aria-hidden>
                  <ResponsiveContainer width={120} height={32}>
                    <LineChart data={agent.points}>
                      <Line
                        type="monotone"
                        dataKey="score"
                        stroke={SPARKLINE_COLOR}
                        strokeWidth={1.5}
                        dot={false}
                        isAnimationActive={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </span>
                <span className={`fleet-health-panel__badge ${scoreBadgeClass(score)}`}>
                  {score}
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
