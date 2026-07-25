import type {
  CapabilityAgent,
  CapabilityMatrix,
  OverrideRequest,
  OverrideResponse,
} from '../features/capability/types'
import { api } from './client'

export interface CapabilityClient {
  getMatrix(): Promise<CapabilityMatrix>
  applyOverride(req: OverrideRequest): Promise<OverrideResponse>
}

/**
 * Live `CapabilityClient` backed by the generated `openapi-fetch` client.
 *
 * As of AAASM-5090 `GET /api/v1/capability/matrix` is a real projection of the
 * agent registry and the policy capability cascade, so there is no mock client
 * left to fall back to. The hand-written feature-side types in
 * `features/capability/types` and the codegen'd types in `api/generated/schema`
 * are structurally identical for these payloads, so the response body casts at
 * the API boundary are safe.
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
      return { updated: (data.updated ?? []) as CapabilityAgent[] }
    },
  }
}

export const capabilityClient: CapabilityClient = createApiCapabilityClient()
