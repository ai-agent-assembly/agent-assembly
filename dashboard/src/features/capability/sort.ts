import type { CapabilityAgent, Decision, Resource, Verb } from './types'

export type SortDirection = 'asc' | 'desc' | null

export interface SortState {
  resourceId: string | null
  direction: SortDirection
}

export const NO_SORT: SortState = { resourceId: null, direction: null }

const DECISION_WEIGHT: Record<Decision, number> = {
  na: 0,
  allow: 1,
  narrow: 2,
  approval: 3,
  deny: 4,
}

export function nextSortState(prev: SortState, resourceId: string): SortState {
  if (prev.resourceId !== resourceId) return { resourceId, direction: 'desc' }
  if (prev.direction === 'desc') return { resourceId, direction: 'asc' }
  return NO_SORT
}

export function sortAgents(
  agents: CapabilityAgent[],
  resources: Resource[],
  verb: Verb,
  sort: SortState,
): CapabilityAgent[] {
  if (!sort.resourceId || !sort.direction) return agents
  const ids = resources.map((r) => r.id)
  if (!ids.includes(sort.resourceId)) return agents
  const factor = sort.direction === 'asc' ? 1 : -1
  return [...agents].sort((a, b) => {
    const da = (a.caps[sort.resourceId as string]?.[verb] ?? 'na') as Decision
    const db = (b.caps[sort.resourceId as string]?.[verb] ?? 'na') as Decision
    return factor * (DECISION_WEIGHT[da] - DECISION_WEIGHT[db])
  })
}
