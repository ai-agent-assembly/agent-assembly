import type { Certain } from '../../lib/truthfulness'

// Member roles are the gateway's real policy-RBAC role ids, not a separate
// "membership tier" vocabulary. Keeping them identical to the ids returned by
// `GET /api/v1/iam/roles` is what lets the Roles-tab cards join member counts
// onto each role (AAASM-5068 vocab-seam fix). Order = privilege, high → low.
export const ROLES = ['org_admin', 'team_admin', 'developer', 'viewer', 'auditor'] as const
export type Role = (typeof ROLES)[number]

export const MEMBER_STATUSES = ['active', 'invited', 'suspended'] as const
export type MemberStatus = (typeof MEMBER_STATUSES)[number]

export interface Member {
  id: string
  email: string
  name: string
  role: Role
  status: MemberStatus
  last_active: string | null
  /** Team ids this member belongs to; drives the members-table Teams column. */
  teams?: readonly string[]
}

export interface MemberPage {
  items: Member[]
  page: number
  page_size: number
  total: number
}

export interface InviteMemberInput {
  email: string
  role: Role
}

export interface UpdateMemberRoleInput {
  id: string
  role: Role
}

export const API_KEY_SCOPES = [
  'read:members',
  'write:members',
  'read:policies',
  'write:policies',
  'read:audit',
  'admin',
] as const
export type ApiKeyScope = (typeof API_KEY_SCOPES)[number]

export const API_KEY_STATUSES = ['active', 'revoked'] as const
export type ApiKeyStatus = (typeof API_KEY_STATUSES)[number]

/**
 * One entry in the "Recent activity" timeline shown in IdentityDetailCard
 * (AAASM-1396). Until the gateway exposes per-identity audit-event queries,
 * these are seeded inline alongside the ApiKey record.
 */
export interface RecentActivityEntry {
  /** Stable id for React key + test lookup. */
  id: string
  /** ISO 8601 timestamp. */
  timestamp: string
  /** Short verb like "called", "rotated", "scoped". */
  action: string
  /** Human-readable target (e.g. "GET /api/v1/agents", "key rotated by alice"). */
  target: string
}

export interface ApiKey {
  id: string
  label: string
  prefix: string
  scopes: ApiKeyScope[]
  status: ApiKeyStatus
  created_at: string
  last_used: string | null
  /**
   * AAASM-1396 IdentityDetailCard fields. Backed by the in-memory store
   * until `/v1/iam/api-keys` lands; defaults are seeded in apiKeys.ts.
   */
  owner: string
  role: string
  assigned_policies: string[]
  recent_activity: RecentActivityEntry[]
}

export interface GenerateApiKeyInput {
  label: string
  scopes: ApiKeyScope[]
}

/** Returned exactly once at generation. The `secret` MUST NOT be cached. */
export interface GeneratedApiKey {
  id: string
  prefix: string
  secret: string
}

/**
 * Liveness words the registry is known to emit (`AgentStatus` in the OpenAPI
 * schema). `AgentResponse.status` is declared as a free-form `string`, so this
 * list drives **styling only** — an unrecognised word still renders verbatim
 * rather than being coerced into one of these.
 *
 * The previous vocabulary here was `online` / `offline` / `degraded`, which no
 * endpoint has ever emitted: it existed to type four hardcoded agents
 * (AAASM-5110). A closed union with no producer behind it is an invitation to
 * invent rows that satisfy it.
 */
export const AGENT_STATUS_TONES = ['active', 'idle', 'suspended'] as const
export type AgentStatusTone = (typeof AGENT_STATUS_TONES)[number]

/**
 * One row of the Roles tab's agent registry, projected from `AgentResponse`
 * (`GET /api/v1/agents`).
 *
 * Fields the registry does not carry are `Certain` absences rather than
 * values. That is the load-bearing part: the old shape declared
 * `owner_team: string` and a closed `status` union, and the only way to
 * satisfy those types without an endpoint was to fabricate agents. A
 * `Certain` field cannot be satisfied by invention — whoever builds one has
 * to name the state the absence is in.
 */
export interface Agent {
  readonly id: string
  readonly name: string
  /**
   * Team that owns this agent. Permanently absent: `GET /api/v1/agents`
   * models no owning team for a registered agent.
   */
  readonly owner_team: Certain<string>
  /** Runtime status, verbatim from the registry. */
  readonly status: Certain<string>
  /** Timestamp of the agent's most recent event (`AgentResponse.last_event`). */
  readonly last_seen: Certain<string>
}

/** One scope's contribution to an agent's capability cascade. */
export interface CascadeScopeGrants {
  /** Wire-format scope label, e.g. `global`, `team:platform`. */
  readonly scope: string
  readonly allow: readonly string[]
  readonly deny: readonly string[]
}

/**
 * An agent's effective capabilities plus the cascade they were resolved from
 * (`GET /api/v1/agents/{id}/capabilities`).
 *
 * `sources` is the evidence, not decoration: an empty `sources` is the
 * AAASM-5106 condition — the gateway resolved no policy document, so an empty
 * `allow`/`deny` means *nothing was evaluated*, not *nothing is granted*. The
 * panel has to tell those apart, which is why the raw cascade is carried
 * through rather than flattened into a permission list.
 */
export interface AgentPermissionCascade {
  readonly agentId: string
  readonly allow: readonly string[]
  readonly deny: readonly string[]
  readonly sources: readonly CascadeScopeGrants[]
}
