import type { ActionVolumeSeries } from './useActionVolumeQuery'
import type { RangeOption } from './urlState'
import { clampChartValue } from './chartDomain'

type ChartRow = Record<string, number>

// Largest absolute time value a JS Date can represent; Intl.DateTimeFormat
// throws "Invalid time value" (RangeError) outside ±this. A malformed 200
// response can carry such a value, so tick formatting must not assume it fits.
const MAX_TIME = 8.64e15
const TICK_PLACEHOLDER = '—'

function dateTimeFormatFor(range: RangeOption): Intl.DateTimeFormat {
  if (range === '24h') {
    return new Intl.DateTimeFormat('en', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })
  }
  if (range === '7d') {
    return new Intl.DateTimeFormat('en', { weekday: 'short' })
  }
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' })
}

export function makeTickFormatter(range: RangeOption): (t: number) => string {
  const fmt = dateTimeFormatFor(range)
  return t =>
    Number.isFinite(t) && Math.abs(t) <= MAX_TIME ? fmt.format(t) : TICK_PLACEHOLDER
}

export function transformSeries(series: ActionVolumeSeries[]): ChartRow[] {
  const rowMap = new Map<number, ChartRow>()
  for (const s of series) {
    for (const pt of s.points) {
      if (!rowMap.has(pt.t)) rowMap.set(pt.t, { t: pt.t })
      rowMap.get(pt.t)![s.key] = clampChartValue(pt.value)
    }
  }
  return Array.from(rowMap.values()).sort((a, b) => a['t'] - b['t'])
}
