import type { FleetAgent } from './fleetTypes'

/**
 * Controlled state for the Fleet page filter bar.
 *
 * `framework` and `status` use `"all"` as the sentinel "no filter" value
 * to mirror the segmented-button selection in `design/v1/fleet.jsx`.
 */
export interface FleetFilters {
  q: string
  framework: string
  status: string
  flaggedOnly: boolean
}

export const DEFAULT_FLEET_FILTERS: FleetFilters = {
  q: '',
  framework: 'all',
  status: 'all',
  flaggedOnly: false,
}

/** Apply filter state to a list of `FleetAgent` view-models. */
export function applyFleetFilters(
  agents: readonly FleetAgent[],
  filters: FleetFilters,
): FleetAgent[] {
  const q = filters.q.trim().toLowerCase()
  return agents.filter((a) => {
    if (q) {
      const haystack = `${a.name} ${a.owner ?? ''}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    if (filters.framework !== 'all' && a.framework !== filters.framework) return false
    if (filters.status !== 'all' && a.status !== filters.status) return false
    if (filters.flaggedOnly && !a.flagged) return false
    return true
  })
}

/** Distinct framework values present in the current agent list. */
export function frameworkOptions(agents: readonly FleetAgent[]): string[] {
  return Array.from(new Set(agents.map((a) => a.framework))).sort()
}
