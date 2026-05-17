import type {
  CapabilityAgent,
  CapabilityMatrix,
  OverrideRequest,
  OverrideResponse,
} from '../features/capability/types'
import { CAPABILITY_MATRIX_FIXTURE } from '../features/capability/fixtures'
import { api } from './client'

const MOCK_LATENCY_MS = 120

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

export interface CapabilityClient {
  getMatrix(): Promise<CapabilityMatrix>
  applyOverride(req: OverrideRequest): Promise<OverrideResponse>
}

function applyOverrideToAgents(
  agents: CapabilityAgent[],
  req: OverrideRequest,
): CapabilityAgent[] {
  return agents.map((agent) => {
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
  })
}

export function createMockCapabilityClient(
  options: { latencyMs?: number; failOverride?: boolean } = {},
): CapabilityClient {
  const latency = options.latencyMs ?? MOCK_LATENCY_MS
  let state: CapabilityMatrix = clone(CAPABILITY_MATRIX_FIXTURE)
  return {
    async getMatrix() {
      await delay(latency)
      return clone(state)
    },
    async applyOverride(req) {
      await delay(latency)
      if (options.failOverride) {
        throw new Error('capability override rejected by gateway (mock)')
      }
      state = { ...state, agents: applyOverrideToAgents(state.agents, req) }
      const updated = state.agents.filter((a) => req.agentIds.includes(a.id))
      return { updated: clone(updated) }
    },
  }
}

/**
 * Live `CapabilityClient` backed by the generated `openapi-fetch` client
 * (AAASM-1433). The hand-written feature-side types in `features/capability/types`
 * and the codegen'd types in `api/generated/schema` are structurally identical
 * for these payloads, so the response body casts at the API boundary are safe.
 */
export function createApiCapabilityClient(): CapabilityClient {
  return {
    async getMatrix() {
      const { data, error } = await api.GET('/api/v1/capability/matrix')
      if (error || !data) {
        throw new Error('capability matrix fetch failed')
      }
      return data as CapabilityMatrix
    },
    async applyOverride(req) {
      const { data, error } = await api.POST('/api/v1/capability/override', {
        body: {
          agentIds: req.agentIds,
          resourceId: req.resourceId,
          verb: req.verb,
          decision: req.decision,
        },
      })
      if (error || !data) {
        throw new Error('capability override rejected by gateway')
      }
      return data as OverrideResponse
    },
  }
}

export const capabilityClient: CapabilityClient = createApiCapabilityClient()
