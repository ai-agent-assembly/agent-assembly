import { ROLES, type Member, type Role } from './types'

/**
 * Static built-in role → capability-grant catalogue.
 *
 * FLAG (AAASM-5042): the gateway exposes no RBAC role→capability grant
 * endpoint. `/api/v1/capability/matrix` describes per-agent capabilities over
 * *resources* (a different concept), and `/api/v1/iam/*` is member / api-key
 * CRUD only — neither answers "which governance capabilities does this human
 * role grant?". Until that endpoint lands (needs an aa-api path owned by the
 * gateway team), the grant lists below are the documented built-in defaults,
 * mirroring `design/v1/hi-fi/identity.jsx`. They are reference data, not live
 * per-tenant grants — the card UI surfaces that caveat, and `buildRoleCards`
 * is the single seam to swap for a live fetch without touching the component.
 */
export interface RoleCapabilityCatalogueEntry {
  description: string
  capabilities: readonly string[]
}

export const ROLE_CAPABILITY_CATALOGUE: Record<Role, RoleCapabilityCatalogueEntry> = {
  Owner: {
    description:
      'Full access — create / delete global policies, manage all teams and members, issue any token scope, approve any action.',
    capabilities: [
      'manage_policies:global',
      'manage_members',
      'approve:any',
      'view_all_logs',
      'manage_budgets',
      'issue_tokens:any',
    ],
  },
  Admin: {
    description:
      'Manage policies and members scoped to assigned teams. Cannot touch global policies or other teams.',
    capabilities: [
      'manage_policies:team',
      'manage_members:team',
      'approve:team',
      'view_logs:team',
      'issue_tokens:team',
    ],
  },
  Member: {
    description:
      'Approve / reject pending actions, suspend / resume agents within assigned teams. No policy or member management.',
    capabilities: ['approve:team', 'suspend_agent:team', 'resume_agent:team', 'view_logs:team'],
  },
  Viewer: {
    description:
      'Read-only access to dashboards, logs, and topology. Cannot take any governance action.',
    capabilities: ['view_logs:all', 'view_topology', 'view_policies', 'view_costs'],
  },
}

/** One role-capability card: role identity + its grants + who holds it. */
export interface RoleCard {
  role: Role
  /** Null when the catalogue has no entry for the role (null-safe render). */
  description: string | null
  capabilities: readonly string[]
  memberCount: number
  assignees: Member[]
}

/**
 * Fold the live member roster (real IAM data) together with the static grant
 * catalogue into one card per built-in role. Member count and assignees are
 * backed by `/iam` members; `description` / `capabilities` come from the
 * catalogue and are null-safe when absent.
 */
export function buildRoleCards(members: readonly Member[]): RoleCard[] {
  return ROLES.map((role) => {
    const entry = ROLE_CAPABILITY_CATALOGUE[role] ?? null
    const assignees = members.filter((m) => m.role === role)
    return {
      role,
      description: entry?.description ?? null,
      capabilities: entry?.capabilities ?? [],
      memberCount: assignees.length,
      assignees,
    }
  })
}
