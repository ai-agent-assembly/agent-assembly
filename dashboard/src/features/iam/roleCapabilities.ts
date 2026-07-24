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
  org_admin: {
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
  team_admin: {
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
  developer: {
    description:
      'Approve / reject pending actions, suspend / resume agents within assigned teams. No policy or member management.',
    capabilities: ['approve:team', 'suspend_agent:team', 'resume_agent:team', 'view_logs:team'],
  },
  viewer: {
    description:
      'Read-only access to dashboards, logs, and topology. Cannot take any governance action.',
    capabilities: ['view_logs:all', 'view_topology', 'view_policies', 'view_costs'],
  },
  auditor: {
    description:
      'Read-only access to audit trails and compliance exports. Cannot take any governance action.',
    capabilities: ['view:audit', 'export:audit'],
  },
}

/** One role-capability card: role identity + its grants + who holds it. */
export interface RoleCard {
  /**
   * Role identifier. A built-in member `Role` in the static-fallback path, or
   * a gateway RBAC role id (e.g. `org_admin`) in the live path — hence a
   * widened `string` rather than the member-only `Role` union.
   */
  role: string
  /** Null when the catalogue has no entry for the role (null-safe render). */
  description: string | null
  capabilities: readonly string[]
  memberCount: number
  assignees: Member[]
}

/**
 * A live role→capability grant as returned by `GET /api/v1/iam/roles`
 * (AAASM-5046). This is the gateway's real policy-RBAC model — roles
 * (`org_admin`, `team_admin`, `developer`, `viewer`, `auditor`) and grants
 * derived server-side from the PolicyMutationRequiredRole table. It is
 * deliberately coarser than the static design catalogue above.
 */
export interface LiveRoleGrant {
  role: string
  description: string
  capabilities: readonly string[]
}

/**
 * Fold the member roster together with capability grants into one card per
 * role. This is the single seam the cards read from (AAASM-5042).
 *
 * When `liveGrants` is present and non-empty, cards reflect the **live**
 * gateway role→capability model: one card per gateway role, grants from the
 * server. Assignees are joined by a case-insensitive role-name match against
 * the member roster — the gateway's authz-role vocabulary and the member
 * assignment vocabulary are currently distinct, so only exact-name matches
 * carry members (no fabricated crosswalk).
 *
 * When `liveGrants` is absent/empty (fetch unavailable), it falls back to the
 * static built-in catalogue keyed by member `Role` — the documented defaults
 * the flag banner explains.
 */
export function buildRoleCards(
  members: readonly Member[],
  liveGrants?: readonly LiveRoleGrant[] | null,
): RoleCard[] {
  if (liveGrants && liveGrants.length > 0) {
    return liveGrants.map((grant) => {
      const assignees = members.filter((m) => m.role.toLowerCase() === grant.role.toLowerCase())
      return {
        role: grant.role,
        description: grant.description || null,
        capabilities: grant.capabilities,
        memberCount: assignees.length,
        assignees,
      }
    })
  }

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
