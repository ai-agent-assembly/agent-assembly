import type { Alert, AlertFilters } from './types'

export function applyClientFilters(
  rows: readonly Alert[],
  filters: AlertFilters,
): readonly Alert[] {
  const q = filters.agentQuery.trim().toLowerCase()
  return rows.filter((r) => {
    if (filters.severities.length && !filters.severities.includes(r.severity)) return false
    if (filters.statuses.length && !filters.statuses.includes(r.status)) return false
    if (q) {
      const haystack = `${r.agentId ?? ''} ${r.ruleName}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
}
