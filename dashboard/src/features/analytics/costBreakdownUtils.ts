import type { CostBucket, CostSegment } from './useCostBreakdownQuery'
import { clampChartValue } from './chartDomain'

export interface SegmentMeta { key: string; name: string }

export function getUniqueSegments(buckets: CostBucket[]): SegmentMeta[] {
  const seen = new Set<string>()
  const result: SegmentMeta[] = []
  for (const b of buckets) {
    for (const s of b.segments) {
      if (!seen.has(s.key)) {
        seen.add(s.key)
        result.push({ key: s.key, name: s.name })
      }
    }
  }
  return result
}

export function computeSegmentTotals(buckets: CostBucket[]): Map<string, number> {
  const totals = new Map<string, number>()
  for (const b of buckets) {
    for (const s of b.segments) {
      totals.set(s.key, (totals.get(s.key) ?? 0) + s.value)
    }
  }
  return totals
}

export function transformBuckets(buckets: CostBucket[]): Record<string, string | number>[] {
  return buckets.map(b => {
    const row: Record<string, string | number> = { label: b.label }
    for (const s of b.segments) {
      row[s.key] = clampChartValue(s.value)
    }
    return row
  })
}

const USD_FORMAT = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 0,
})

// Beyond this magnitude the legend total / tooltip label switches to compact
// currency notation (e.g. $1B, $1T). AAASM-4334's clampChartValue only hardens
// the chart axis domain; this hardens the label *text*. Sibling of AAASM-4195's
// formatDelta finite-guard.
const USD_COMPACT_THRESHOLD = 1e9

const USD_COMPACT_FORMAT = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  notation: 'compact',
  maximumFractionDigits: 1,
})

export function formatUsd(value: number): string {
  // Non-finite (NaN / ±Infinity) → em dash, mirroring formatDelta. These arise
  // from a malformed 200 or a zero-baseline division upstream.
  if (!Number.isFinite(value)) return '—'
  // Cap the display magnitude to the same finite bound AAASM-4334 clamps the
  // chart axis to (CHART_VALUE_LIMIT). A schema-boundary value like
  // ±Number.MAX_VALUE (1.79e308) is finite, so compact notation alone does NOT
  // bound it — Intl still prints a ~300-digit string suffixed with "T". Reusing
  // clampChartValue guarantees the label can never exceed ±$1T.
  const clamped = clampChartValue(value)
  if (Math.abs(clamped) >= USD_COMPACT_THRESHOLD) return USD_COMPACT_FORMAT.format(clamped)
  return USD_FORMAT.format(clamped)
}

export function formatSegment(seg: CostSegment): string {
  return USD_FORMAT.format(seg.value)
}
