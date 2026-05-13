import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { iamQueryKeys } from './queryKeys'
import type { InviteMemberInput, Member, MemberPage, UpdateMemberRoleInput } from './types'

/**
 * In-memory member store.
 *
 * The OpenAPI spec does not yet define `/v1/iam/*` endpoints. Until
 * the gateway lands, this module keeps a single in-process collection
 * that React Query treats as the source of truth, so the UI is fully
 * exercisable and unit-testable without an MSW server. Swap the body
 * of these functions for `api.GET/POST/PATCH` calls once the gateway
 * endpoints exist — the public hook signatures will not change.
 */
const SEED_MEMBERS: Member[] = [
  { id: 'me', email: 'alice@agent-assembly.dev', name: 'Alice Owner', role: 'Owner', status: 'active', last_active: '2026-05-13T10:14:00Z' },
  { id: 'mbr-2', email: 'bob@agent-assembly.dev', name: 'Bob Admin', role: 'Admin', status: 'active', last_active: '2026-05-12T22:01:00Z' },
  { id: 'mbr-3', email: 'carol@agent-assembly.dev', name: 'Carol Member', role: 'Member', status: 'active', last_active: '2026-05-11T08:30:00Z' },
  { id: 'mbr-4', email: 'dave@agent-assembly.dev', name: 'Dave Viewer', role: 'Viewer', status: 'active', last_active: null },
  { id: 'mbr-5', email: 'eve@partner.example', name: 'Eve Partner', role: 'Viewer', status: 'invited', last_active: null },
]

const store: { members: Member[] } = { members: [...SEED_MEMBERS] }

export const CURRENT_USER_ID = 'me'

export const DEFAULT_PAGE_SIZE = 20

function fetchMembersPage(page: number, pageSize: number): Promise<MemberPage> {
  const start = (page - 1) * pageSize
  const items = store.members.slice(start, start + pageSize)
  return Promise.resolve({ items, page, page_size: pageSize, total: store.members.length })
}

export function useMembersQuery(page = 1, pageSize = DEFAULT_PAGE_SIZE) {
  return useQuery({
    queryKey: iamQueryKeys.membersPage(page, pageSize),
    queryFn: () => fetchMembersPage(page, pageSize),
  })
}

export class InviteMemberError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'InviteMemberError'
  }
}

let _inviteSeq = 0

function inviteMember(input: InviteMemberInput): Promise<Member> {
  const exists = store.members.some(
    (m) => m.email.toLowerCase() === input.email.toLowerCase(),
  )
  if (exists) {
    return Promise.reject(new InviteMemberError(`${input.email} is already a member`))
  }
  const created: Member = {
    id: `mbr-invite-${++_inviteSeq}`,
    email: input.email,
    name: input.email.split('@')[0],
    role: input.role,
    status: 'invited',
    last_active: null,
  }
  store.members = [...store.members, created]
  return Promise.resolve(created)
}

export function useInviteMemberMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: InviteMemberInput) => inviteMember(input),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: iamQueryKeys.members() })
    },
  })
}

export class UpdateMemberRoleError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UpdateMemberRoleError'
  }
}

/** Override hook for tests — when set, used in place of the in-memory store. */
let _updateRoleOverride: ((input: UpdateMemberRoleInput) => Promise<Member>) | null = null

function updateMemberRole(input: UpdateMemberRoleInput): Promise<Member> {
  if (_updateRoleOverride) return _updateRoleOverride(input)
  const idx = store.members.findIndex((m) => m.id === input.id)
  if (idx === -1) return Promise.reject(new UpdateMemberRoleError(`member ${input.id} not found`))
  const next: Member = { ...store.members[idx], role: input.role }
  store.members = [...store.members.slice(0, idx), next, ...store.members.slice(idx + 1)]
  return Promise.resolve(next)
}

export interface UpdateMemberRoleContext {
  snapshots: [readonly unknown[], MemberPage | undefined][]
}

export function useUpdateMemberRoleMutation() {
  const queryClient = useQueryClient()
  return useMutation<Member, Error, UpdateMemberRoleInput, UpdateMemberRoleContext>({
    mutationFn: updateMemberRole,
    onMutate: async (input) => {
      await queryClient.cancelQueries({ queryKey: iamQueryKeys.members() })
      const snapshots = queryClient.getQueriesData<MemberPage>({
        queryKey: iamQueryKeys.members(),
      })
      for (const [key, page] of snapshots) {
        if (!page) continue
        queryClient.setQueryData<MemberPage>(key, {
          ...page,
          items: page.items.map((m) => (m.id === input.id ? { ...m, role: input.role } : m)),
        })
      }
      return { snapshots }
    },
    onError: (_err, _input, context) => {
      if (!context) return
      for (const [key, snapshot] of context.snapshots) {
        queryClient.setQueryData(key, snapshot)
      }
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: iamQueryKeys.members() })
    },
  })
}

_iamInternal.setUpdateRoleOverride = (
  fn: ((input: UpdateMemberRoleInput) => Promise<Member>) | null,
): void => {
  _updateRoleOverride = fn
}

/** Test-only helpers — reset the seed between specs. */
export const _iamInternal: {
  reset: () => void
  snapshot: () => readonly Member[]
  store: { members: Member[] }
  setUpdateRoleOverride: (fn: ((input: UpdateMemberRoleInput) => Promise<Member>) | null) => void
} = {
  reset(): void {
    store.members = [...SEED_MEMBERS]
    _updateRoleOverride = null
    _inviteSeq = 0
  },
  snapshot(): readonly Member[] {
    return store.members
  },
  store,
  setUpdateRoleOverride: () => {},
}
