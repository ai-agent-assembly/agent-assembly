import { useMemo } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useApprovalAnalyticsQuery } from './useApprovalAnalyticsQuery'
import { CHART_COLORBLIND_PALETTE } from './chartPalette'
import type { ApprovalAnalyticsResponse } from './useApprovalAnalyticsQuery'

function formatTta(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`
  const h = Math.floor(m / 60)
  const rem = m % 60
  return rem > 0 ? `${h}h ${rem}m` : `${h}h`
}

function formatRate(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`
}

function buildDonutData(data: ApprovalAnalyticsResponse) {
  return [
    { name: 'Approved', value: data.byOutcome.approved },
    { name: 'Rejected', value: data.byOutcome.rejected },
    { name: 'Expired',  value: data.byOutcome.expired  },
  ]
}

const DONUT_COLORS = [
  CHART_COLORBLIND_PALETTE[2], // bluish green — approved
  CHART_COLORBLIND_PALETTE[5], // vermilion — rejected
  CHART_COLORBLIND_PALETTE[3], // yellow — expired
]

export function ApprovalAnalyticsPanel() {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = useApprovalAnalyticsQuery(filters)

  const donutData = useMemo(() => (data ? buildDonutData(data) : []), [data])

  return (
    <div className="approval-analytics-panel" data-testid="approval-analytics-panel">
      <div className="approval-analytics-panel__header">
        <h2 className="approval-analytics-panel__title">Approval Analytics</h2>
      </div>

      {isPending ? (
        <div className="approval-analytics-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="approval-analytics-panel__error">Failed to load approval data.</p>
      ) : !data ? null : (
        <div className="approval-analytics-panel__body">
          <div className="approval-analytics-panel__stats">
            <div className="approval-analytics-panel__stat">
              <span className="approval-analytics-panel__stat-value">
                {data.volume.toLocaleString()}
              </span>
              <span className="approval-analytics-panel__stat-label">Total volume</span>
            </div>
            <div className="approval-analytics-panel__stat">
              <span className="approval-analytics-panel__stat-value">
                {formatTta(data.medianTta)}
              </span>
              <span className="approval-analytics-panel__stat-label">Median TTA</span>
            </div>
            <div className="approval-analytics-panel__stat">
              <span className="approval-analytics-panel__stat-value">
                {formatRate(data.approvalRate)}
              </span>
              <span className="approval-analytics-panel__stat-label">Approval rate</span>
            </div>
          </div>

          <div className="approval-analytics-panel__donut" data-testid="approval-donut">
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={48}
                  outerRadius={72}
                  dataKey="value"
                  isAnimationActive={false}
                >
                  {donutData.map((entry, i) => (
                    <Cell key={entry.name} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />
                  ))}
                </Pie>
                {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                <Tooltip formatter={(value: any) => [value.toLocaleString(), '']} />
              </PieChart>
            </ResponsiveContainer>
            <ul className="approval-analytics-panel__legend" aria-label="Outcome legend">
              {donutData.map((entry, i) => (
                <li key={entry.name} className="approval-analytics-panel__legend-item">
                  <span
                    className="approval-analytics-panel__legend-swatch"
                    style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }}
                  />
                  <span>{entry.name}</span>
                  <span className="approval-analytics-panel__legend-count">
                    {entry.value.toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
