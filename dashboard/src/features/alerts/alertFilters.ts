// Client-side narrowing for the alerts feed (AAASM-5122).
//
// `list_alerts` in openapi/v1.yaml declares only `page` and `per_page`, and
// `aa-api` extracts `Query<PaginationParams>` alone — so severity / status /
// agent / time-range were never applied by the server no matter what the client
// sent. The controls have to narrow something real, so they narrow the loaded
// page here. That is a smaller claim than server-side filtering, and the page
// states the difference (see the truncation notice on AlertsPage).

import type { Alert, AlertFilters, TimeRangePreset } from './types'

/** Preset window lengths in milliseconds. `custom` is bounded by from/to. */
const PRESET_WINDOW_MS: Record<Exclude<TimeRangePreset, 'custom'>, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
}

/** Inclusive bounds in epoch milliseconds; `null` means unbounded on that side. */
export interface TimeWindow {
  readonly fromMs: number | null
  readonly toMs: number | null
}

function parseMs(value: string | null): number | null {
  if (!value) return null
  const ms = Date.parse(value)
  return Number.isNaN(ms) ? null : ms
}

/**
 * Resolve the selected range to absolute bounds.
 *
 * A `custom` range with unparseable endpoints resolves to an unbounded window
 * rather than an empty one: a half-typed datetime must not silently hide every
 * alert and leave the operator reading an empty feed as "nothing fired".
 */
export function resolveTimeWindow(filters: AlertFilters, now: number): TimeWindow {
  if (filters.timeRange === 'custom') {
    return { fromMs: parseMs(filters.customFrom), toMs: parseMs(filters.customTo) }
  }
  return { fromMs: now - PRESET_WINDOW_MS[filters.timeRange], toMs: null }
}

/**
 * Narrow a loaded page by every control the filter bar and stats strip drive.
 *
 * An alert whose `firstFiredAt` cannot be parsed is kept, not dropped — an
 * unreadable timestamp is a reason to show the row and let the operator judge
 * it, never a reason to make it disappear from a governance feed.
 */
export function applyClientFilters(
  rows: readonly Alert[],
  filters: AlertFilters,
  now: number = Date.now(),
): readonly Alert[] {
  const q = filters.agentQuery.trim().toLowerCase()
  const { fromMs, toMs } = resolveTimeWindow(filters, now)
  return rows.filter((r) => {
    if (filters.severities.length && !filters.severities.includes(r.severity)) return false
    if (filters.statuses.length && !filters.statuses.includes(r.status)) return false
    if (q) {
      const haystack = `${r.agentId ?? ''} ${r.ruleName}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    const firedMs = Date.parse(r.firstFiredAt)
    if (Number.isNaN(firedMs)) return true
    if (fromMs !== null && firedMs < fromMs) return false
    if (toMs !== null && firedMs > toMs) return false
    return true
  })
}

/**
 * Add or remove one value from a multi-select filter list.
 *
 * Shared by the filter-bar chips and the stats tiles so both drive the single
 * filter model identically.
 */
export function toggleFilterValue<T>(list: readonly T[], value: T): readonly T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value]
}
