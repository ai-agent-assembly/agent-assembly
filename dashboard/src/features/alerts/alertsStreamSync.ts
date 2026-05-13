import type { QueryClient } from '@tanstack/react-query'
import { alertsQueryKeys } from './endpoints'
import type { Alert } from './types'

/**
 * Apply an incoming `alert.fire` event to every active alerts list cache
 * (one per filter combination). The new alert is prepended; if an entry
 * with the same id already exists it is replaced in place so the FIRING
 * → SUPPRESSED → FIRING cycle stays correct.
 */
export function applyFire(client: QueryClient, incoming: Alert): void {
  client.setQueriesData<readonly Alert[] | undefined>(
    { queryKey: [alertsQueryKeys.alerts] },
    (prev) => {
      if (!prev) return prev
      const idx = prev.findIndex((a) => a.id === incoming.id)
      return idx === -1 ? [incoming, ...prev] : prev.map((a) => (a.id === incoming.id ? incoming : a))
    },
  )
}

/**
 * Apply an `alert.resolve` event by updating the matching row in place
 * across every list cache.
 */
export function applyResolve(client: QueryClient, incoming: Alert): void {
  client.setQueriesData<readonly Alert[] | undefined>(
    { queryKey: [alertsQueryKeys.alerts] },
    (prev) => (prev ? prev.map((a) => (a.id === incoming.id ? incoming : a)) : prev),
  )
}

/**
 * Apply an `alert.silence` event the same way as resolve — the WS payload
 * already carries the updated alert with `status: 'SUPPRESSED'`.
 */
export function applySilence(client: QueryClient, incoming: Alert): void {
  applyResolve(client, incoming)
}
