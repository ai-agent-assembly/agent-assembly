import type { CapabilityAgent } from './types'

export interface CapabilityFilters {
  search: string
  framework: string
  owner: string
  mode: string
  trustMax: number | null
}

export const EMPTY_FILTERS: CapabilityFilters = {
  search: '',
  framework: 'any',
  owner: 'any',
  mode: 'any',
  trustMax: null,
}

export function applyFilters(
  agents: CapabilityAgent[],
  filters: CapabilityFilters,
): CapabilityAgent[] {
  const q = filters.search.trim().toLowerCase()
  return agents.filter((a) => {
    if (filters.framework !== 'any' && a.framework !== filters.framework) return false
    if (filters.owner !== 'any' && a.owner !== filters.owner) return false
    if (filters.mode !== 'any' && a.mode !== filters.mode) return false
    if (filters.trustMax !== null && a.trust > filters.trustMax) return false
    if (!q) return true
    return (
      a.name.toLowerCase().includes(q) ||
      a.framework.toLowerCase().includes(q) ||
      a.owner.toLowerCase().includes(q) ||
      a.id.toLowerCase().includes(q)
    )
  })
}
