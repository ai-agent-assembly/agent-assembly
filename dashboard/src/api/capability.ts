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
 * are structurally identical for these payloads, but that is a compile-time
 * claim about shape, not a runtime guarantee about content — "structurally
 * identical" was previously (mis)cited here as making the response body casts
 * below "safe" outright (AAASM-5217 audit). It doesn't: `data as
 * CapabilityMatrix` still hands every consumer raw wire values wearing
 * unenforced `Decision` / `Verb` / `AgentStatus` annotations.
 *
 * The cast is accepted-risk only because every field it produces that is ever
 * used as an object/Map lookup key is validated downstream before that lookup
 * happens: `Decision` values read off `caps[...]` go through
 * `decisionMeta()`/`decisionWeight()` (`features/capability/types.ts`,
 * `features/capability/sort.ts`), which check membership in the `Decision`
 * union before indexing. Every other field on this payload (ids, names,
 * timestamps, trust scores) is rendered as opaque display value, never used as
 * a key, so an unrecognised or prototype-inherited value there is a display
 * glitch, not a lookup hazard.
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
