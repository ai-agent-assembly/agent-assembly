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
