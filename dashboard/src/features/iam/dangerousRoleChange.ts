import type { Member, Role } from './types'

// Role is the closed member-role union (`ROLES` in ./types); both call sites
// pass an already-typed `Role`, not a raw wire string — narrow-union Record
// gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const ROLE_RANK: Record<Role, number> = {
  org_admin: 4,
  team_admin: 3,
  developer: 2,
  viewer: 1,
  auditor: 0,
}

export interface DangerousRoleChange {
  reason: 'self' | 'last-owner'
  message: string
}

export function detectDangerousRoleChange(
  member: Member,
  next: Role,
  context: { allMembers: readonly Member[]; currentUserId: string | null },
): DangerousRoleChange | null {
  if (next === member.role) return null

  if (member.id === context.currentUserId && ROLE_RANK[next] < ROLE_RANK[member.role]) {
    return {
      reason: 'self',
      message: 'You are lowering your own role. You may lose access to this page after the change.',
    }
  }

  if (member.role === 'org_admin' && next !== 'org_admin') {
    const ownerCount = context.allMembers.filter((m) => m.role === 'org_admin').length
    if (ownerCount <= 1) {
      return {
        reason: 'last-owner',
        message: 'This member is the last Org Admin. Downgrading them will leave the workspace without an org administrator.',
      }
    }
  }

  return null
}
