import type { QueryClient } from '@tanstack/react-query'
import { ALERTS_LIST_KEY } from './endpoints'
import type { AlertsPageResult } from './api'
import type { Alert } from './types'

type CachedPage = AlertsPageResult | undefined

/**
 * Rewrite the cached list page.
 *
 * Scoped to `ALERTS_LIST_KEY` rather than the bare `alerts` root: the root also
 * matches every single-alert detail cache, whose payload is an object, and a
 * list-shaped updater run over it throws.
 */
function updateListPage(
  client: QueryClient,
  update: (page: AlertsPageResult) => AlertsPageResult,
): void {
  client.setQueriesData<CachedPage>({ queryKey: ALERTS_LIST_KEY }, (prev) =>
    prev ? update(prev) : prev,
  )
}

/**
 * Apply an incoming `alert.fire` event to the cached alerts page. The new
 * alert is prepended; if an entry with the same id already exists it is
 * replaced in place so the FIRING → SUPPRESSED → FIRING cycle stays correct.
 *
 * A genuinely new alert also increments `total`, because the server's count has
 * grown too. Leaving `total` untouched would understate the fleet for as long
 * as the cache lives, and the page renders `total` as the authority on how much
 * the visible list omits. A `null` total stays `null`: not knowing the total
 * plus one is still not knowing it.
 */
export function applyFire(client: QueryClient, incoming: Alert): void {
  updateListPage(client, (page) => {
    if (page.items.some((a) => a.id === incoming.id)) {
      return {
        ...page,
        items: page.items.map((a) => (a.id === incoming.id ? incoming : a)),
      }
    }
    return {
      ...page,
      items: [incoming, ...page.items],
      total: page.total === null ? null : page.total + 1,
    }
  })
}

/**
 * Apply an `alert.resolve` event by updating the matching row in place. An
 * event for a row outside the loaded page is a no-op — the row is not there to
 * update, and inventing it would put an alert on screen the page never listed.
 */
export function applyResolve(client: QueryClient, incoming: Alert): void {
  updateListPage(client, (page) => ({
    ...page,
    items: page.items.map((a) => (a.id === incoming.id ? incoming : a)),
  }))
}

/**
 * Apply an `alert.silence` event the same way as resolve — the WS payload
 * already carries the updated alert with `status: 'SUPPRESSED'`.
 */
export function applySilence(client: QueryClient, incoming: Alert): void {
  applyResolve(client, incoming)
}
