/**
 * Roles-tab data layer: the agent registry and each agent's capability
 * cascade.
 *
 * ── Why this module was rewritten (AAASM-5110) ──────────────────────────────
 *
 * It previously held `SEED_AGENTS` (four invented agents — `support-agent/cx`,
 * `code-review/platform`, `data-analyst/analytics`, `deploy-agent/devops`) and
 * `SEED_PERMISSIONS`, a grant table attributing capabilities to policies that
 * do not exist (`support-agent-policy-v2`, `deploy-agent-policy-v1`) and roles
 * nothing issues (`agent.operator`). Neither fetcher touched the network, and
 * the panels rendered both behind a full loading / error / empty apparatus with
 * no disclaimer — so the fiction was indistinguishable from production data on
 * a governance surface.
 *
 * Both are now backed by endpoints that exist:
 *
 *  - `GET /api/v1/agents` — the same registry the Fleet page reads;
 *  - `GET /api/v1/agents/{id}/capabilities` — the merged allow/deny set plus
 *    the per-scope contribution of every policy in the agent's cascade, which
 *    the OpenAPI summary already names as the dashboard's inherited-permissions
 *    source.
 *
 * What the endpoints do not carry is reported as an explicit absence rather
 * than back-filled. That is the whole point: the previous seed existed because
 * the local types demanded values the API never had.
 */
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import { absent, certain } from '../../lib/truthfulness'
import { iamQueryKeys } from './queryKeys'
import type { Agent, AgentPermissionCascade } from './types'

type AgentResponse = components['schemas']['AgentResponse']
type EffectivePermissionsResponse = components['schemas']['EffectivePermissionsResponse']

/**
 * Team ownership is a permanent gap in this projection, not a transient one.
 *
 * `AgentResponse` has no team field at all — the concept exists elsewhere
 * (`AgentTree.team_id`, the topology endpoints) but the registry list does not
 * carry it, so no amount of waiting or retrying makes it appear here.
 * `not-supported` is the honest state; `unknown` would tell an operator to
 * refresh, and a back-filled team name is what AAASM-5110 is about.
 */
const OWNER_TEAM_UNSUPPORTED = absent<string>(
  'not-supported',
  'GET /api/v1/agents carries no owning team for a registered agent',
)

/**
 * The outer variant of the runtime status this endpoint emits.
 *
 * `aa-api` builds the field as `format!("{:?}", r.status)`
 * (`aa-api/src/routes/agents.rs:135`) over `aa_gateway::registry::AgentStatus`
 * (`aa-gateway/src/registry/mod.rs:77-83`), so the wire values are Rust `Debug`
 * renderings, not a lowercase enum:
 *
 *  - `Active`
 *  - `Deregistered`
 *  - `Suspended(<reason>)` — where the reason is itself a variant, one of
 *    `BudgetExceeded`, `Manual`, `ParentDeregistered`, or the struct-shaped
 *    `ParentSuspended { parent_agent_id: [..] }`.
 *
 * Callers therefore cannot classify a status by equality: `Suspended` carries a
 * payload, so an exact-match lookup would never hit it and every suspended
 * agent would fall through to the neutral tone. This returns the text before
 * the first `(`, which is the outer variant name under `Debug`'s grammar.
 *
 * Note this is deliberately *not* the lowercase `active | idle | suspended`
 * enum in the OpenAPI schema: that one belongs to `AgentNode` in the
 * capability-matrix projection (`aa-api/src/models/capability.rs:95`), a
 * different endpoint. Keying off it here left the whole tone map dead.
 */
export function agentStatusVariant(status: string): string {
  const payloadAt = status.indexOf('(')
  return payloadAt === -1 ? status : status.slice(0, payloadAt)
}

/** Project one registry entry, lifting every gap into the vocabulary. */
export function toRegistryAgent(raw: AgentResponse): Agent {
  return {
    id: raw.id,
    name: raw.name,
    owner_team: OWNER_TEAM_UNSUPPORTED,
    status: certain(raw.status, 'unknown', 'The registry reported no status for this agent'),
    // `last_event` is null until the agent emits its first event. That is an
    // honest "we do not know when this was last seen", not "never seen" — a
    // freshly registered agent has simply not reported yet.
    last_seen: certain(
      raw.last_event,
      'unknown',
      'The registry has recorded no event for this agent',
    ),
  }
}

export function useAgentsQuery() {
  return useQuery({
    queryKey: iamQueryKeys.agents(),
    queryFn: async (): Promise<Agent[]> => {
      // AAASM-4892: /agents returns a paginated { items, total } object.
      const { data, error } = await api.GET('/api/v1/agents', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch agents')
      return (data?.items ?? []).map(toRegistryAgent)
    },
  })
}

/** Project the capability response, preserving the cascade as evidence. */
export function toPermissionCascade(
  agentId: string,
  raw: EffectivePermissionsResponse,
): AgentPermissionCascade {
  return {
    agentId,
    allow: raw.allow,
    deny: raw.deny,
    sources: raw.sources.map((source) => ({
      scope: source.scope,
      allow: source.allow,
      deny: source.deny,
    })),
  }
}

export function useAgentPermissionsQuery(agentId: string | null) {
  return useQuery({
    queryKey: agentId
      ? iamQueryKeys.agentPermissions(agentId)
      : iamQueryKeys.agentPermissionsIdle(),
    queryFn: async (): Promise<AgentPermissionCascade> => {
      const id = agentId as string
      const { data, error } = await api.GET('/api/v1/agents/{id}/capabilities', {
        params: { path: { id } },
      })
      // A 200 with no body answers nothing about this agent's permissions, so
      // it fails the same way a transport error does rather than resolving to
      // an empty cascade — an empty cascade is a *claim* the panel renders
      // differently (AAASM-5106), and a missing body cannot support it.
      if (error || !data) throw new Error('Failed to fetch agent permissions')
      return toPermissionCascade(id, data)
    },
    enabled: agentId !== null,
  })
}
