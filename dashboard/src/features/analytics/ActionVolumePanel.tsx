import { useMemo } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useActionVolumeQuery } from './useActionVolumeQuery'
import { useChartPalette } from './useChartPalette'
import { transformSeries } from './actionVolumeUtils'
import type { RangeOption } from './urlState'

function makeTickFormatter(range: RangeOption): (t: number) => string {
  if (range === '24h') {
    return t =>
      new Intl.DateTimeFormat('en', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      }).format(t)
  }
  if (range === '7d') {
    return t => new Intl.DateTimeFormat('en', { weekday: 'short' }).format(t)
  }
  return t =>
    new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' }).format(t)
}

export function ActionVolumePanel() {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = useActionVolumeQuery(filters)
  const palette = useChartPalette('categorical')

  const rawSeries = data?.series
  const series = useMemo(() => rawSeries ?? [], [rawSeries])
  const chartData = useMemo(() => transformSeries(series), [series])
  const tickFormatter = useMemo(() => makeTickFormatter(filters.range), [filters.range])

  return (
    <div className="action-volume-panel" data-testid="action-volume-panel">
      <h2 className="action-volume-panel__title">Action Volume</h2>

      {/* Per-series test anchors — not visible in UI */}
      {series.map(s => (
        <span
          key={s.key}
          data-testid={`action-volume-line-${s.key}`}
          aria-hidden
          className="action-volume-panel__line-anchor"
        />
      ))}

      {isPending ? (
        <div className="action-volume-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="action-volume-panel__error">Failed to load action volume data.</p>
      ) : series.length === 0 ? (
        <div className="action-volume-panel__empty">
          <p>No data for the selected filters.</p>
          <a href="/docs/analytics#no-data">Why am I seeing nothing?</a>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--surface-card-border)" />
            <XAxis
              dataKey="t"
              tickFormatter={tickFormatter}
              tick={{ fontSize: 12, fill: 'var(--text-muted)' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fontSize: 12, fill: 'var(--text-muted)' }}
              axisLine={false}
              tickLine={false}
              width={40}
            />
            <Tooltip />
            {series.map((s, i) => (
              <Line
                key={s.key}
                type="monotone"
                dataKey={s.key}
                name={s.name}
                stroke={palette[i % palette.length]}
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
