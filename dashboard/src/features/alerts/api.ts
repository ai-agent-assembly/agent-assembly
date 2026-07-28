import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationResult,
  type UseQueryResult,
} from '@tanstack/react-query'
import { getToken } from '../../auth/tokenStorage'
import { ALERTS_LIST_KEY, alertDetailKey, alertsEndpoints, alertsQueryKeys } from './endpoints'
import { parseAlertList } from './parseAlert'
import type {
  Alert,
  AlertDetail,
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
  const token = getToken()
  return token ? { Authorization: `Bearer ${token}` } : {}
}

/**
 * Generic fetch helper shared by every alerts endpoint. `return (await
 * response.json()) as T` (AAASM-5217 audit) is a bare cast: nothing here
 * canonicalises the body against `T`.
 *
 * Accepted-risk, not blanket-safe: the list path (`fetchAlertsPage` below)
 * pipes its response through `readAlertsPage` → `parseAlertList`, which
 * validates `severity`/`status` before an `Alert` exists (AAASM-5149). The
 * single-alert-detail and rules/destinations/silence paths that also call
 * this helper (`useAlertQuery`, `useAlertRulesQuery`, `useDestinationsQuery`,
 * etc.) do not get that same normalisation — but every place their
 * `severity`/`status` fields are used as an object-lookup key
 * (`SeverityBadge`, `StatusBadge`) validates the value itself immediately
 * before indexing, rather than trusting the annotation this cast asserts. No
 * other field this helper's callers return is ever used as a lookup key —
 * `metric`, `operator`, ids, and timestamps are all rendered as opaque
 * display values.
 */
export async function alertsFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  // A write-side header accumulator (built fresh per call from known static
  // keys + a spread), not a wire-keyed lookup table — AAASM-5245 gap 1.
  // eslint-disable-next-line no-restricted-syntax
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...authHeader(),
    ...(init.headers as Record<string, string> | undefined),
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

// ── useAlertsPageQuery ────────────────────────────────────────────────────

/**
 * One page of `GET /api/v1/alerts`, with the envelope's own account of how much
 * it left behind.
 *
 * `total` / `page` / `perPage` are nullable because a caller must be able to
 * tell "the server said 214" from "the server did not say". Defaulting a
 * missing `total` to `items.length` would assert that a page is the whole
 * fleet — the exact truncation-as-completeness claim AAASM-5123 is about.
 */
export interface AlertsPageResult {
  readonly items: readonly Alert[]
  /** Alerts visible to the caller across all pages, per the envelope. */
  readonly total: number | null
  /** 1-indexed page number echoed by the server. */
  readonly page: number | null
  /** Page size echoed by the server (the API defaults to 50, max 100). */
  readonly perPage: number | null
}

/** Raw `PaginatedAlertResponse` shape, as far as this client trusts it. */
interface RawAlertsPage {
  items?: unknown
  total?: unknown
  page?: unknown
  per_page?: unknown
}

function finiteOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

/**
 * Normalise the envelope without inventing anything.
 *
 * `items` is *parsed*, not cast (AAASM-5149). It used to be
 * `Array.isArray(body?.items) ? (body.items as readonly Alert[]) : []`, which
 * asserted the dashboard's vocabulary over whatever the wire happened to send
 * and folded a malformed envelope to an empty fleet. Both halves were the same
 * fail-open: `severity`/`status` never matched a live payload, so every derived
 * count was zero, and zero is a confident claim that nothing is wrong.
 *
 * `parseAlertList` throws `AlertShapeError` on anything it cannot read. The
 * throw is the point — it reaches `certainFromQuery` as `unavailable`, which is
 * what an unreadable answer actually is. `total` / `page` / `perPage` keep their
 * nullable treatment: a missing count still reports "unknown", never "0 of 0".
 */
function readAlertsPage(body: RawAlertsPage | null | undefined): AlertsPageResult {
  return {
    items: parseAlertList(body?.items),
    total: finiteOrNull(body?.total),
    page: finiteOrNull(body?.page),
    perPage: finiteOrNull(body?.per_page),
  }
}

/**
 * Fetch one page of alerts.
 *
 * No query string: `list_alerts` in `openapi/v1.yaml` declares **only** `page`
 * and `per_page`, and `aa-api` extracts `Query<PaginationParams>` alone. The
 * `severity` / `status` / `agent` / `range` parameters this client used to send
 * were accepted by the transport and discarded by the handler, so the UI
 * reported an unfiltered list as a filtered one. Narrowing now happens over the
 * returned page — see `applyClientFilters` (AAASM-5122).
 */
function fetchAlertsPage(): Promise<AlertsPageResult> {
  return alertsFetch<RawAlertsPage>(alertsEndpoints.list).then(readAlertsPage)
}

/**
 * The paginated envelope, for callers that must be able to say how much of the
 * fleet the page covers.
 */
export function useAlertsPageQuery(): UseQueryResult<AlertsPageResult, Error> {
  return useQuery({
    queryKey: ALERTS_LIST_KEY,
    queryFn: fetchAlertsPage,
    placeholderData: (prev) => prev,
  })
}

/**
 * The alert rows alone, for callers that do not present a total.
 *
 * `filters` is accepted for call-site compatibility and deliberately **not**
 * sent: see `fetchAlertsPage`. It is not part of the cache key either, because
 * every filter selection produces the same request — keying on it only
 * multiplied identical cache entries and refired the query on each chip click.
 * Callers that need narrowing apply `applyClientFilters` to the result.
 *
 * Declared as an overload whose implementation binds no parameter, so the
 * argument stays in the public signature (existing call sites keep compiling)
 * without a discarded binding in the body. `void filters` would have done the
 * same job, but this codebase avoids the `void` operator — see
 * `src/lib/ignorePromise.ts`, written for the same reason.
 */
export function useAlertsQuery(
  filters?: AlertFilters,
): UseQueryResult<readonly Alert[], Error>
export function useAlertsQuery(): UseQueryResult<readonly Alert[], Error> {
  return useQuery({
    queryKey: ALERTS_LIST_KEY,
    queryFn: fetchAlertsPage,
    select: (page) => page.items,
    placeholderData: (prev) => prev,
  })
}

// ── useAlertQuery (single alert detail) ───────────────────────────────────

export function useAlertQuery(
  id: string | null | undefined,
): UseQueryResult<AlertDetail, Error> {
  return useQuery({
    queryKey: alertDetailKey(id ?? ''),
    queryFn: () => alertsFetch<AlertDetail>(alertsEndpoints.detail(id as string)),
    enabled: !!id,
  })
}

// ── useResolveAlertMutation (AAASM-5121) ──────────────────────────────────

export interface ResolveAlertInput {
  alertId: string
  /** Optional note; accepted by the API though the in-memory store drops it. */
  reason?: string
}

/**
 * Acknowledge/resolve an alert.
 *
 * The request body is sent even when empty: `resolve_alert` declares
 * `requestBody.required: true`, so an omitted body is a 4xx rather than a
 * default-empty resolution.
 */
export function useResolveAlertMutation(): UseMutationResult<
  Alert,
  Error,
  ResolveAlertInput
> {
  const client = useQueryClient()
  return useMutation({
    mutationFn: ({ alertId, reason }) =>
      alertsFetch<Alert>(alertsEndpoints.resolve(alertId), {
        method: 'POST',
        body: JSON.stringify({ reason: reason ?? null }),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: [alertsQueryKeys.alerts] }),
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
