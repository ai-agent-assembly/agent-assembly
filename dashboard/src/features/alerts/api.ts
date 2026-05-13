import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query'
import { alertsEndpoints, alertsQueryKeys } from './endpoints'
import type {
  Alert,
  AlertFilters,
  AlertRule,
  AlertRuleInput,
  Destination,
  DestinationInput,
  DestinationTestResult,
  Silence,
  SilenceInput,
} from './types'

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

// ── useAlertQuery (single alert detail) ───────────────────────────────────

export function useAlertQuery(id: string | null | undefined): UseQueryResult<Alert, Error> {
  return useQuery({
    queryKey: [alertsQueryKeys.alerts, id ?? ''],
    queryFn: () => alertsFetch<Alert>(alertsEndpoints.detail(id as string)),
    enabled: !!id,
  })
}

// ── Alert rules — list + create / update / delete ─────────────────────────

export function useAlertRulesQuery(): UseQueryResult<readonly AlertRule[], Error> {
  return useQuery({
    queryKey: [alertsQueryKeys.alertRules],
    queryFn: () => alertsFetch<readonly AlertRule[]>(alertsEndpoints.rules),
  })
}

function invalidateRules(client: ReturnType<typeof useQueryClient>): Promise<void> {
  return client.invalidateQueries({ queryKey: [alertsQueryKeys.alertRules] })
}

export function useCreateAlertRuleMutation(): UseMutationResult<
  AlertRule,
  Error,
  AlertRuleInput
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input) =>
      alertsFetch<AlertRule>(alertsEndpoints.rules, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    onSuccess: () => invalidateRules(client),
  })
}

export function useUpdateAlertRuleMutation(): UseMutationResult<
  AlertRule,
  Error,
  { id: string; input: AlertRuleInput }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }) =>
      alertsFetch<AlertRule>(alertsEndpoints.rule(id), {
        method: 'PUT',
        body: JSON.stringify(input),
      }),
    onSuccess: () => invalidateRules(client),
  })
}

export function useDeleteAlertRuleMutation(): UseMutationResult<void, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id) =>
      alertsFetch<void>(alertsEndpoints.rule(id), { method: 'DELETE' }),
    onSuccess: () => invalidateRules(client),
  })
}

// ── Destinations — list + create / update / delete / test ────────────────

function invalidateDestinations(
  client: ReturnType<typeof useQueryClient>,
): Promise<void> {
  return client.invalidateQueries({ queryKey: [alertsQueryKeys.destinations] })
}

export function useDestinationsQuery(): UseQueryResult<readonly Destination[], Error> {
  return useQuery({
    queryKey: [alertsQueryKeys.destinations],
    queryFn: () => alertsFetch<readonly Destination[]>(alertsEndpoints.destinations),
  })
}

export function useCreateDestinationMutation(): UseMutationResult<
  Destination,
  Error,
  DestinationInput
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input) =>
      alertsFetch<Destination>(alertsEndpoints.destinations, {
        method: 'POST',
        body: JSON.stringify(input),
      }),
    onSuccess: () => invalidateDestinations(client),
  })
}

export function useUpdateDestinationMutation(): UseMutationResult<
  Destination,
  Error,
  { id: string; input: DestinationInput }
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ id, input }) =>
      alertsFetch<Destination>(alertsEndpoints.destination(id), {
        method: 'PUT',
        body: JSON.stringify(input),
      }),
    onSuccess: () => invalidateDestinations(client),
  })
}

export function useDeleteDestinationMutation(): UseMutationResult<void, Error, string> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (id) =>
      alertsFetch<void>(alertsEndpoints.destination(id), { method: 'DELETE' }),
    onSuccess: () => invalidateDestinations(client),
  })
}

export function useTestDestinationMutation(): UseMutationResult<
  DestinationTestResult,
  Error,
  { id: string; severity?: string; message?: string }
> {
  return useMutation({
    mutationFn: ({ id, severity, message }) =>
      alertsFetch<DestinationTestResult>(alertsEndpoints.destinationTest(id), {
        method: 'POST',
        body: JSON.stringify({ severity, message }),
      }),
  })
}

// ── useSilenceAlertMutation ───────────────────────────────────────────────

export function useSilenceAlertMutation(): UseMutationResult<
  Silence,
  Error,
  SilenceInput
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: (input) =>
      alertsFetch<Silence>(alertsEndpoints.silence, {
        method: 'POST',
        body: JSON.stringify({
          alert_id: input.alertId,
          duration_seconds: input.durationSeconds,
          reason: input.reason,
        }),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: [alertsQueryKeys.alerts] }),
  })
}
