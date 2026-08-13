// Central registry of every URL the alerts feature talks to.
//
// Each backend Story (AAASM-1385 / 1386 / 1387 / 1388 / 1389) commits to one
// of these paths. Keeping them in a single module means: when the backend
// ships and codegen catches up, only this file plus the typed `api` client
// need to change.

export const alertsEndpoints = {
  list: '/api/v1/alerts',
  detail: (id: string) => `/api/v1/alerts/${encodeURIComponent(id)}`,
  rules: '/api/v1/alerts/rules',
  rule: (id: string) => `/api/v1/alerts/rules/${encodeURIComponent(id)}`,
  silence: '/api/v1/alerts/silence',
  /**
   * `POST /api/v1/alerts/:id/resolve` — the acknowledge path (AAASM-5121).
   *
   * Unlike the rest of this table this one *is* in `openapi/v1.yaml` today
   * (`operationId: resolve_alert`), and it is idempotent: resolving an
   * already-resolved alert returns the same record. It shipped without any UI
   * affordance, which is why `applyResolve` could only ever be driven by an
   * externally-resolved alert arriving over the WebSocket.
   */
  resolve: (id: string) => `/api/v1/alerts/${encodeURIComponent(id)}/resolve`,
  destinations: '/api/v1/alerts/destinations',
  destination: (id: string) => `/api/v1/alerts/destinations/${encodeURIComponent(id)}`,
  destinationTest: (id: string) =>
    `/api/v1/alerts/destinations/${encodeURIComponent(id)}/test`,
  /** WebSocket upgrade for fire / resolve / silence events (AAASM-1389). */
  websocket: '/api/v1/alerts/ws',
} as const

/** Tanstack Query cache key roots. Hooks use these so invalidation stays consistent. */
export const alertsQueryKeys = {
  alerts: 'alerts',
  alertRules: 'alert-rules',
  destinations: 'alert-destinations',
} as const

/**
 * Cache key for the paginated `GET /api/v1/alerts` envelope.
 *
 * Carries a `'list'` discriminator because the WebSocket sync helpers reach for
 * every cache under the `alerts` root with `setQueriesData`, and that prefix
 * also matches the single-alert detail caches. Without the discriminator a
 * `fire` event ran a list-shaped updater over an `AlertDetail` object.
 *
 * Deliberately carries no filter state: `list_alerts` in `openapi/v1.yaml`
 * declares only `page` and `per_page`, so two different filter selections
 * produce byte-identical requests and must share one cache entry (AAASM-5122).
 */
export const ALERTS_LIST_KEY = [alertsQueryKeys.alerts, 'list'] as const

/** Cache key for one alert's detail payload. */
export function alertDetailKey(id: string): readonly [string, string, string] {
  return [alertsQueryKeys.alerts, 'detail', id]
}
