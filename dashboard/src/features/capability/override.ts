import { OVERRIDABLE_DECISIONS } from './types'
import type { CapabilityMatrix, OverridableDecision, OverrideRequest } from './types'

/**
 * Narrow a raw `<select>` value to a decision the override endpoint accepts.
 *
 * The bulk bar previously cast the change event straight to `Decision`, which
 * is how a value the gateway 400s on could become component state and then be
 * painted optimistically. Parsing instead of asserting means the widened set
 * has to come back through here if AAASM-5094 ever computes those cells.
 */
export function isOverridableDecision(value: string): value is OverridableDecision {
  return (OVERRIDABLE_DECISIONS as readonly string[]).includes(value)
}

export function applyOverrideLocal(
  matrix: CapabilityMatrix,
  req: OverrideRequest,
): CapabilityMatrix {
  return {
    ...matrix,
    agents: matrix.agents.map((agent) => {
      if (!req.agentIds.includes(agent.id)) return agent
      const existing = agent.caps[req.resourceId]
      if (!existing) return agent
      return {
        ...agent,
        caps: {
          ...agent.caps,
          [req.resourceId]: { ...existing, [req.verb]: req.decision },
        },
      }
    }),
  }
}
