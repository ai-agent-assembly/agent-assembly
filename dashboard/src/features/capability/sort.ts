import { isDecision, type CapabilityAgent, type Decision, type Resource, type Verb } from './types'

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

/**
 * Weight for a sort comparison, validating the wire-derived decision first
 * (AAASM-5217). `a.caps[id]?.[verb]` is raw wire data wearing an unenforced
 * `Decision` annotation — the capability matrix is cast wholesale at the API
 * boundary (`api/capability.ts`) — so a hostile or malformed payload can send
 * `"__proto__"` or `"constructor"` here. An unrecognised value weighs the same
 * as `na` rather than resolving to `undefined` (making every comparison
 * `NaN`) or an inherited `Object.prototype` member.
 */
function decisionWeight(decision: Decision): number {
  return isDecision(decision) ? DECISION_WEIGHT[decision] : DECISION_WEIGHT.na
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
    const da = a.caps[sort.resourceId as string]?.[verb] ?? 'na'
    const db = b.caps[sort.resourceId as string]?.[verb] ?? 'na'
    return factor * (decisionWeight(da) - decisionWeight(db))
  })
}
