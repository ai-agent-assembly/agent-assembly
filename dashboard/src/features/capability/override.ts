import type { CapabilityMatrix, OverrideRequest } from './types'

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
