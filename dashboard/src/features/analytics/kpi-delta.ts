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

export function formatDelta(delta: number): string {
  const sign = delta > 0 ? '+' : ''
  return `${sign}${(delta * 100).toFixed(1)}%`
}
