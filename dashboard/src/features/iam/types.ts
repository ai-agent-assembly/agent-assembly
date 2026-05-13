export const ROLES = ['Owner', 'Admin', 'Member', 'Viewer'] as const
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

export interface ApiKey {
  id: string
  label: string
  prefix: string
  scopes: ApiKeyScope[]
  status: ApiKeyStatus
  created_at: string
  last_used: string | null
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

export const AGENT_STATUSES = ['online', 'offline', 'degraded'] as const
export type AgentStatus = (typeof AGENT_STATUSES)[number]

export interface Agent {
  id: string
  name: string
  owner_team: string
  status: AgentStatus
  last_seen: string | null
}

export const INHERITANCE_KINDS = ['team', 'role', 'policy'] as const
export type InheritanceKind = (typeof INHERITANCE_KINDS)[number]

export interface InheritanceSource {
  kind: InheritanceKind
  /** Display name of the team / role / policy that granted this permission. */
  name: string
  granted_at: string
}

export interface EffectivePermission {
  /** Permission identifier, e.g. `policies.read`, `audit.export`. */
  permission: string
  source: InheritanceSource
}

export interface AgentPermissions {
  agent_id: string
  effective: EffectivePermission[]
}
