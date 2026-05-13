import type { CostBucket, CostSegment } from './useCostBreakdownQuery'

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
      row[s.key] = s.value
    }
    return row
  })
}

const USD_FORMAT = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 0,
})

export function formatUsd(value: number): string {
  return USD_FORMAT.format(value)
}

export function formatSegment(seg: CostSegment): string {
  return USD_FORMAT.format(seg.value)
}
