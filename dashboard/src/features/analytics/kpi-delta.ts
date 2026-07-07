export type KpiMetric = 'agents' | 'invocations' | 'p99' | 'cost' | 'anomalies'

export interface KpiResponse {
  metric: KpiMetric
  value: number
  delta: number  // fractional change vs previous equivalent window, e.g. 0.12 = +12%
  unit?: string
}

// Returns true when the delta represents a good/positive trend for the metric.
// Lower is better for latency, cost, and anomaly count.
export function isDeltaPositive(metric: KpiMetric, delta: number): boolean {
  switch (metric) {
    case 'p99':
    case 'cost':
    case 'anomalies':
      return delta <= 0
    default:
      return delta >= 0
  }
}

// Threshold beyond which we switch to compact notation (100x = 10,000%)
const LARGE_DELTA_THRESHOLD = 100

// Intl formatter for large percentage values: e.g. 12345% -> +12K%
const compactFormatter = new Intl.NumberFormat('en-US', {
  notation: 'compact',
  maximumFractionDigits: 1,
})

export function formatDelta(delta: number): string {
  // Guard against non-finite values (Infinity, -Infinity, NaN) which occur
  // when the prior-window baseline is 0 or data is malformed.
  if (!Number.isFinite(delta)) {
    return '—'
  }

  const sign = delta > 0 ? '+' : ''
  const percent = delta * 100

  // Use compact notation for very large deltas to prevent overflow
  if (Math.abs(delta) >= LARGE_DELTA_THRESHOLD) {
    return `${sign}${compactFormatter.format(Math.abs(percent))}%`
  }

  return `${sign}${percent.toFixed(1)}%`
}
