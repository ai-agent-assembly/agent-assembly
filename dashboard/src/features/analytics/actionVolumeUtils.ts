import type { ActionVolumeSeries } from './useActionVolumeQuery'

type ChartRow = Record<string, number>

export function transformSeries(series: ActionVolumeSeries[]): ChartRow[] {
  const rowMap = new Map<number, ChartRow>()
  for (const s of series) {
    for (const pt of s.points) {
      if (!rowMap.has(pt.t)) rowMap.set(pt.t, { t: pt.t })
      rowMap.get(pt.t)![s.key] = pt.value
    }
  }
  return Array.from(rowMap.values()).sort((a, b) => (a['t'] as number) - (b['t'] as number))
}
