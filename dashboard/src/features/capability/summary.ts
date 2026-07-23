import type { CapabilityAgent, Resource, Verb } from './types'

/**
 * Aggregate counts for the matrix summary row. Every field is derived from the
 * already-loaded matrix for the currently displayed verb — no extra fetch — so
 * the tiles always agree with the cells rendered in the grid.
 */
export interface CapabilitySummary {
  /** Cells whose effective decision for `verb` is `allow`. */
  allow: number
  /** Cells narrowed to a sub-scope for `verb`. */
  narrow: number
  /** Cells denied outright for `verb`. */
  deny: number
  /** Distinct agents carrying a recent flag (verb-independent). */
  flaggedAgents: number
}

/**
 * Count effective decisions across the visible agents × resources grid for one
 * verb. Mirrors the per-cell decision the grid renders (`caps[resource][verb]`,
 * defaulting to `na`), so the summary can never drift from what the user sees.
 */
export function summarizeMatrix(
  agents: CapabilityAgent[],
  resources: Resource[],
  verb: Verb,
): CapabilitySummary {
  let allow = 0
  let narrow = 0
  let deny = 0
  for (const agent of agents) {
    for (const resource of resources) {
      const decision = agent.caps[resource.id]?.[verb] ?? 'na'
      if (decision === 'allow') allow += 1
      else if (decision === 'narrow') narrow += 1
      else if (decision === 'deny') deny += 1
    }
  }
  return {
    allow,
    narrow,
    deny,
    flaggedAgents: agents.filter((a) => a.flagged).length,
  }
}
