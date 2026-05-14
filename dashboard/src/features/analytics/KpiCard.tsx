import { isDeltaPositive, formatDelta } from './kpi-delta'
import type { KpiMetric } from './kpi-delta'

interface KpiCardProps {
  metric: KpiMetric
  label: string
  value: number | undefined
  delta: number | undefined
  unit?: string
  isLoading: boolean
  isError: boolean
}

const DELTA_POSITIVE_COLOR = 'var(--trend-positive)'
const DELTA_NEGATIVE_COLOR = 'var(--trend-negative)'

export function KpiCard({ metric, label, value, delta, unit, isLoading, isError }: KpiCardProps) {
  return (
    <div className="kpi-card" data-testid={`kpi-${metric}`}>
      <span className="kpi-card__label">{label}</span>
      {isLoading ? (
        <>
          <div className="kpi-card__skeleton kpi-card__skeleton--value" aria-hidden />
          <div className="kpi-card__skeleton kpi-card__skeleton--delta" aria-hidden />
        </>
      ) : isError ? (
        <span className="kpi-card__error">—</span>
      ) : (
        <>
          <span className="kpi-card__value">
            {value?.toLocaleString()}
            {unit && <span className="kpi-card__unit"> {unit}</span>}
          </span>
          {delta !== undefined && (
            <span
              className="kpi-card__delta"
              style={{ color: isDeltaPositive(metric, delta) ? DELTA_POSITIVE_COLOR : DELTA_NEGATIVE_COLOR }}
            >
              {formatDelta(delta)}
            </span>
          )}
        </>
      )}
    </div>
  )
}
