import { useQuery } from '@tanstack/react-query'
import { iamQueryKeys } from './queryKeys'
import type { Member, MemberPage } from './types'

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

/** Test-only helpers — reset the seed between specs. */
export const _iamInternal = {
  reset(): void {
    store.members = [...SEED_MEMBERS]
  },
  snapshot(): readonly Member[] {
    return store.members
  },
  store,
}
