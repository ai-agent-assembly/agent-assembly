import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useCostBreakdownQuery } from './useCostBreakdownQuery'
import { useChartPalette } from './useChartPalette'
import { SegmentedControl } from './SegmentedControl'
import {
  getUniqueSegments,
  computeSegmentTotals,
  transformBuckets,
  formatUsd,
} from './costBreakdownUtils'
import { GROUP_BY_OPTIONS, decodeCostBy } from './costBreakdown'

const USD_TICK = (value: number) =>
  new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value)

export function CostBreakdownPanel() {
  const { filters } = useAnalyticsFilters()
  const [searchParams, setSearchParams] = useSearchParams()
  const groupBy = decodeCostBy(searchParams)

  const setGroupBy = (next: typeof groupBy) => {
    setSearchParams(
      prev => {
        const p = new URLSearchParams(prev)
        p.set('costBy', next)
        return p
      },
      { replace: true },
    )
  }

  const { data, isPending, isError } = useCostBreakdownQuery(groupBy, filters)
  const palette = useChartPalette('colorblind')

  const rawBuckets = data?.buckets
  const buckets = useMemo(() => rawBuckets ?? [], [rawBuckets])
  const chartData = useMemo(() => transformBuckets(buckets), [buckets])
  const segments = useMemo(() => getUniqueSegments(buckets), [buckets])
  const totals = useMemo(() => computeSegmentTotals(buckets), [buckets])

  const [hidden, setHidden] = useState<Set<string>>(new Set())

  const toggleSegment = (key: string) => {
    setHidden(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const visibleSegments = useMemo(
    () => segments.filter(s => !hidden.has(s.key)),
    [segments, hidden],
  )

  return (
    <div className="cost-breakdown-panel" data-testid="cost-breakdown-panel">
      <div className="cost-breakdown-panel__header">
        <h2 className="cost-breakdown-panel__title">Cost Breakdown</h2>
        <SegmentedControl
          options={GROUP_BY_OPTIONS}
          value={groupBy}
          onChange={setGroupBy}
          testIdPrefix="cost-breakdown-toggle"
        />
      </div>

      {isPending ? (
        <div className="cost-breakdown-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="cost-breakdown-panel__error">Failed to load cost data.</p>
      ) : buckets.length === 0 ? (
        <div className="cost-breakdown-panel__empty">
          <p>No cost data for the selected filters.</p>
          <a href="/docs/analytics#no-data">Why am I seeing nothing?</a>
        </div>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={chartData} margin={{ top: 8, right: 16, left: 8, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fontSize: 12, fill: '#6b7280' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tickFormatter={USD_TICK}
                tick={{ fontSize: 12, fill: '#6b7280' }}
                axisLine={false}
                tickLine={false}
                width={56}
              />
              <Tooltip
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                formatter={(value: any) => [typeof value === 'number' ? formatUsd(value) : String(value ?? ''), '']}
              />
              {visibleSegments.map((seg, i) => (
                <Bar
                  key={seg.key}
                  dataKey={seg.key}
                  name={seg.name}
                  stackId="stack"
                  fill={palette[i % palette.length]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>

          {/* Custom legend with segment totals */}
          <ul className="cost-breakdown-panel__legend" aria-label="Segment legend">
            {segments.map((seg, i) => {
              const isHidden = hidden.has(seg.key)
              return (
                <li key={seg.key} className="cost-breakdown-panel__legend-item">
                  <button
                    type="button"
                    className={`cost-breakdown-panel__legend-btn${isHidden ? ' cost-breakdown-panel__legend-btn--hidden' : ''}`}
                    onClick={() => toggleSegment(seg.key)}
                    aria-pressed={!isHidden}
                  >
                    <span
                      className="cost-breakdown-panel__legend-swatch"
                      style={{ background: palette[i % palette.length] }}
                    />
                    <span className="cost-breakdown-panel__legend-name">{seg.name}</span>
                    <span className="cost-breakdown-panel__legend-total">
                      {formatUsd(totals.get(seg.key) ?? 0)}
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        </>
      )}
    </div>
  )
}
