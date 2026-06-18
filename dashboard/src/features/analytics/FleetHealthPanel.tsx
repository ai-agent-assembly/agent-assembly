import { useMemo } from 'react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useFleetHealthQuery } from './useFleetHealthQuery'
import { CHART_CATEGORICAL_PALETTE } from './chartPalette'
import type { AgentHealth } from './useFleetHealthQuery'

const SPARKLINE_COLOR = CHART_CATEGORICAL_PALETTE[0]

function currentScore(agent: AgentHealth): number {
  const last = agent.points.at(-1)
  return last ? last.score : 0
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

  function renderBody() {
    if (isPending) {
      return <div className="fleet-health-panel__skeleton" aria-hidden />
    }
    if (isError) {
      return <p className="fleet-health-panel__error">Failed to load fleet health data.</p>
    }
    if (agents.length === 0) {
      return (
        <div className="fleet-health-panel__empty">
          <p>No agents reporting in this window.</p>
        </div>
      )
    }
    return (
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
    )
  }

  return (
    <div className="fleet-health-panel" data-testid="fleet-health-panel">
      <div className="fleet-health-panel__header">
        <h2 className="fleet-health-panel__title">Fleet Health</h2>
      </div>

      {renderBody()}
    </div>
  )
}
