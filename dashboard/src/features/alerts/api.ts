import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { alertsEndpoints, alertsQueryKeys } from './endpoints'
import type { Alert, AlertFilters } from './types'

// ── Fetch helper ──────────────────────────────────────────────────────────
//
// The endpoints listed in `endpoints.ts` (other than `list`) are not yet in
// `openapi/v1.yaml` — see backend Stories AAASM-1385 / 1386 / 1387 / 1388 /
// 1389. The typed `openapi-fetch` client therefore cannot reach them; this
// thin wrapper mirrors its auth/baseUrl handling using raw `fetch` so every
// alerts hook stays consistent. Swap call sites back to the typed client
// once the schema regenerates.

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? ''

function authHeader(): Record<string, string> {
  const token = localStorage.getItem('aa_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

export async function alertsFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...authHeader(),
    ...((init.headers as Record<string, string>) ?? {}),
  }
  if (init.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  const response = await fetch(`${BASE_URL}${path}`, { ...init, headers })
  if (!response.ok) {
    throw new Error(`${init.method ?? 'GET'} ${path} failed: ${response.status}`)
  }
  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

// ── useAlertsQuery ────────────────────────────────────────────────────────

function buildAlertsQueryString(filters: AlertFilters): string {
  const sp = new URLSearchParams()
  filters.severities.forEach((s) => sp.append('severity', s))
  filters.statuses.forEach((s) => sp.append('status', s))
  if (filters.agentQuery.trim()) sp.set('agent', filters.agentQuery.trim())
  if (filters.timeRange !== 'custom') {
    sp.set('range', filters.timeRange)
  } else {
    if (filters.customFrom) sp.set('from', filters.customFrom)
    if (filters.customTo) sp.set('to', filters.customTo)
  }
  const qs = sp.toString()
  return qs ? `?${qs}` : ''
}

export function useAlertsQuery(
  filters: AlertFilters,
): UseQueryResult<readonly Alert[], Error> {
  return useQuery({
    queryKey: [alertsQueryKeys.alerts, filters],
    queryFn: () =>
      alertsFetch<readonly Alert[]>(
        `${alertsEndpoints.list}${buildAlertsQueryString(filters)}`,
      ),
    placeholderData: (prev) => prev,
  })
}
