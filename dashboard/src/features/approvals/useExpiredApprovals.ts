import { useSyncExternalStore } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import type { Approval } from './api'

const EXPIRED_KEY = ['approvals', 'expired'] as const
const ACTIVE_KEY = ['approvals'] as const
const EMPTY: Approval[] = []

// Imperative dispatcher — usable from non-React contexts (the WS handler in
// `useApprovalsStream`) and from React event handlers (the `onExpire` callback
// of `ApprovalCountdown`). Both paths converge here, satisfying the parent
// AAASM-1478 requirement that the two triggers result in the same state update.
//
// Removes the row from the active `['approvals']` cache and appends it (with
// status flipped to `'expired'`) to the client-only `['approvals','expired']`
// cache. Idempotent — calling twice with the same id does not duplicate.
export function expireApproval(qc: QueryClient, id: string): void {
  const active = qc.getQueryData<Approval[]>([...ACTIVE_KEY]) ?? []
  const row = active.find((a) => a.id === id)
  if (!row) {
    // No-op when the WS event references a row we don't have (page-load race,
    // already-decided row, etc.). Avoids spurious entries in the expired list.
    return
  }
  qc.setQueryData<Approval[]>([...ACTIVE_KEY], active.filter((a) => a.id !== id))
  qc.setQueryData<Approval[]>([...EXPIRED_KEY], (prev) => {
    const existing = prev ?? []
    if (existing.some((a) => a.id === id)) return existing
    return [...existing, { ...row, status: 'expired' }]
  })
}

export function useExpiredApprovals(): { expired: Approval[]; expire: (id: string) => void } {
  const qc = useQueryClient()
  const expiredHash = JSON.stringify(EXPIRED_KEY)

  const expired = useSyncExternalStore(
    (callback) => {
      const unsubscribe = qc.getQueryCache().subscribe((event) => {
        if (event.query.queryHash === expiredHash) callback()
      })
      return unsubscribe
    },
    () => qc.getQueryData<Approval[]>([...EXPIRED_KEY]) ?? EMPTY,
    () => EMPTY,
  )

  return {
    expired,
    expire: (id: string) => expireApproval(qc, id),
  }
}
