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
