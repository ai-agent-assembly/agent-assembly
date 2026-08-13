/**
 * What the sensitive-data surface fetches, and what each answer means
 * (AAASM-5360, over the AAASM-5359 routes).
 *
 * Seven routes, all read-scoped and all tenant-confined server-side:
 * `summary`, `timeseries`, `breakdown`, `events`, `events/{event_id}`,
 * `top-offenders`, and the admin-only `export`.
 *
 * ## Failure is classified, not flattened
 *
 * `certainFromShapedQuery` maps every rejection to `unavailable` — "the request
 * for this value failed" — which is right for a panel and wrong for the page.
 * Four of the statuses these routes return are *different facts about the
 * deployment or the caller*, and collapsing them loses the operator's next step:
 *
 *  - **403** — the caller may not read this. A real state. Rendering it as an
 *    empty chart says "there is nothing here", which is a different and false
 *    claim about someone else's tenant.
 *  - **503** — the projection is not enabled on this deployment. The API is
 *    explicit that this is *not* the same as an empty window: "the projection is
 *    off" and "the window was quiet" are different answers, and a governance
 *    surface that renders the first as the second reports a clean posture for a
 *    system that is not recording.
 *  - **400** — a cross-tenant caller named no organisation. There is no unscoped
 *    read, and this dashboard deliberately sends no `org_id` (see `filters.ts`),
 *    so a token with no org scope cannot use this page at all. Saying so beats
 *    an empty chart.
 *  - **401** — the session is not authenticated. Retrying will not help; signing
 *    in will.
 *
 * {@link readAccess} is the one place that mapping happens, and the page
 * switches on it before it renders any figure.
 *
 * ## Every body is decoded before anything reads it
 *
 * No hook here declares its data as a response type: what arrived is `unknown`
 * until `certainFromShapedQuery` has put it through the matching decoder in
 * `schema.ts`, and `unknown` has no fields to reach for. A fold that skips the
 * decoder does not compile (AAASM-5366).
 *
 * ## The export is not a query
 *
 * It is `RequireAdmin` **plus** an explicit `acknowledge_export=true`, and the
 * server writes an access record naming the principal *before* it produces the
 * body. So it is not something a page performs on mount, on focus, or on a
 * cache miss: {@link requestComplianceExport} is a plain function a component
 * calls from a confirmed click, and nothing in this module fetches it otherwise.
 * A `useQuery` for it would make a followed link release a tenant's governance
 * record, which is the exact thing the acknowledgement exists to prevent.
 */
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import {
  certainFromShapedQuery,
  type Certain,
  type Decoder,
  type QueryOutcome,
} from '../../lib/truthfulness'
import { filterCacheKey, filterQuery, type SensitiveDataFilters } from './filters'
import {
  decodeBreakdown,
  decodeEventDetail,
  decodeEvents,
  decodeSummary,
  decodeTimeseries,
  decodeTopOffenders,
  type MetricDimension,
  type SensitiveDataBreakdownResponse,
  type SensitiveDataEventDetailResponse,
  type SensitiveDataEventsResponse,
  type SensitiveDataSummaryResponse,
  type SensitiveDataTimeseriesResponse,
  type TopOffendersResponse,
} from './schema'

/**
 * A failed sensitive-data read, carrying the status that says *why*.
 *
 * `status` is `0` when the request never reached a server (offline, DNS, CORS):
 * distinct from any HTTP answer, and reported as a generic failure rather than
 * guessed at.
 */
export class SensitiveDataHttpError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'SensitiveDataHttpError'
    this.status = status
  }
}

/** Bucket widths `/timeseries` accepts. */
export const TIMESERIES_BUCKETS = ['1h', '6h', '1d', '7d'] as const
export type TimeseriesBucket = (typeof TIMESERIES_BUCKETS)[number]

/** Dimensions `/top-offenders` ranks by. Not metric labels — see the route doc. */
export const OFFENDER_DIMENSIONS = ['agent', 'root_agent', 'tool', 'destination'] as const
export type OffenderDimension = (typeof OFFENDER_DIMENSIONS)[number]

/** The default page size, matching the API's own. */
export const EVENT_PAGE_SIZE = 100

/** The shape every openapi-fetch call resolves to, as much of it as is read. */
interface FetchResult {
  readonly data?: unknown
  readonly error?: unknown
  readonly response?: { readonly status?: number }
}

/**
 * Turn one openapi-fetch result into a body, or into a status-carrying throw.
 *
 * The body is returned as `unknown`: nothing downstream may read a field off it
 * until a decoder has checked it. The throw carries the HTTP status because
 * {@link readAccess} needs it — a rejection without one collapses `403`, `503`
 * and a dropped connection into the same rendered state.
 *
 * A result with no `response` yields status `0`, which classifies as a generic
 * failure rather than being mistaken for any particular answer.
 */
function unwrap(path: string, result: FetchResult): unknown {
  const status = result.response?.status ?? 0
  if (result.error !== undefined && result.error !== null) {
    throw new SensitiveDataHttpError(status, `${path} failed with status ${status}`)
  }
  if (result.data === undefined || result.data === null) {
    throw new SensitiveDataHttpError(status, `${path} answered with no body (status ${status})`)
  }
  return result.data
}

// ---------------------------------------------------------------------------
// Access classification
// ---------------------------------------------------------------------------

/**
 * What the caller is entitled to see, and whether the deployment can answer.
 *
 * Distinct from a value's absence: these are facts about the *request*, and each
 * one has different operator copy and a different next step. `ok` means the read
 * succeeded — it says nothing about whether the window contained anything, which
 * is `measures.readResult`'s job.
 */
export type SensitiveDataAccess =
  | { readonly kind: 'ok' }
  | { readonly kind: 'pending' }
  /** 401 — not signed in. */
  | { readonly kind: 'unauthenticated' }
  /** 403 — signed in, and not permitted to read this tenant's records. */
  | { readonly kind: 'forbidden' }
  /** 400 — the caller has no tenant scope, and this page sends no `org_id`. */
  | { readonly kind: 'unscoped' }
  /** 503 — the deployment has no sensitive-data projection wired. */
  | { readonly kind: 'projection-off' }
  /** Anything else, including a request that never reached a server. */
  | { readonly kind: 'failed'; readonly detail: string }

/** Classify a query outcome into an access state. */
export function readAccess(outcome: QueryOutcome<unknown>): SensitiveDataAccess {
  const error = outcome.error
  if (error === undefined || error === null) {
    if (outcome.isPending === true) return { kind: 'pending' }
    return { kind: 'ok' }
  }
  if (error instanceof SensitiveDataHttpError) {
    switch (error.status) {
      case 401:
        return { kind: 'unauthenticated' }
      case 403:
        return { kind: 'forbidden' }
      case 400:
        return { kind: 'unscoped' }
      case 503:
        return { kind: 'projection-off' }
      default:
        return { kind: 'failed', detail: error.message }
    }
  }
  return { kind: 'failed', detail: error instanceof Error ? error.message : String(error) }
}

/** Whether an access state permits rendering figures at all. */
export function accessBlocks(access: SensitiveDataAccess): boolean {
  return access.kind !== 'ok'
}

/** The heading rendered for a blocking access state. */
export function accessTitle(access: SensitiveDataAccess): string {
  switch (access.kind) {
    case 'ok':
      return 'Sensitive-data activity'
    case 'pending':
      return 'Reading the sensitive-data projection'
    case 'unauthenticated':
      return 'Not signed in'
    case 'forbidden':
      return 'You cannot view this organisation’s sensitive-data records'
    case 'unscoped':
      return 'This session has no organisation to read'
    case 'projection-off':
      return 'The sensitive-data projection is not enabled here'
    case 'failed':
      return 'The sensitive-data projection could not be read'
  }
}

/** The explanation rendered for a blocking access state. */
export function accessDescription(access: SensitiveDataAccess): string {
  switch (access.kind) {
    case 'ok':
      return ''
    case 'pending':
      return 'Waiting for the projection to answer. Nothing is shown until it does — a figure rendered before the answer arrives would be a figure nobody measured.'
    case 'unauthenticated':
      return 'The gateway rejected these credentials. Sign in again; retrying this page will not change the answer.'
    case 'forbidden':
      return 'The gateway refused this read for the organisation your session is scoped to. Nothing about that organisation’s sensitive-data activity is shown, and nothing about it should be inferred — an empty page here would be a claim, and this is a refusal.'
    case 'unscoped':
      return 'Your session is not confined to an organisation, and the sensitive-data projection has no unscoped read. This dashboard never names an organisation on your behalf, so there is nothing it can ask for. Use a session scoped to the organisation you mean to inspect.'
    case 'projection-off':
      return 'This deployment records no sensitive-data projection, so there are no analytics to report from it. This is not an empty window: an idle deployment and a deployment that is not recording look identical on a chart, and only one of them is safe to read as “nothing happened”.'
    case 'failed':
      return `The read did not complete, so no figure on this page can be stated. ${access.detail}`
  }
}

/**
 * Whether the operator can usefully retry.
 *
 * Only the generic failure. Retrying a `403`, a `401`, a `400` or a `503`
 * re-asks a question that has already been answered, and offering the button
 * implies the answer might change.
 */
export function accessIsRetryable(access: SensitiveDataAccess): boolean {
  return access.kind === 'failed'
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

export const summaryKey = (filters: SensitiveDataFilters) =>
  ['sensitive-data', 'summary', filterCacheKey(filters)] as const

export function useSensitiveDataSummaryQuery(filters: SensitiveDataFilters) {
  return useQuery<unknown>({
    queryKey: summaryKey(filters),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/summary',
        await api.GET('/api/v1/sensitive-data/summary', {
          params: { query: filterQuery(filters) },
        }),
      ),
    retry: false,
  })
}

export const timeseriesKey = (filters: SensitiveDataFilters, bucket: TimeseriesBucket) =>
  ['sensitive-data', 'timeseries', bucket, filterCacheKey(filters)] as const

export function useSensitiveDataTimeseriesQuery(
  filters: SensitiveDataFilters,
  bucket: TimeseriesBucket,
) {
  return useQuery<unknown>({
    queryKey: timeseriesKey(filters, bucket),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/timeseries',
        await api.GET('/api/v1/sensitive-data/timeseries', {
          params: { query: { ...filterQuery(filters), bucket } },
        }),
      ),
    retry: false,
  })
}

export const breakdownKey = (filters: SensitiveDataFilters, groupBy: MetricDimension) =>
  ['sensitive-data', 'breakdown', groupBy, filterCacheKey(filters)] as const

export function useSensitiveDataBreakdownQuery(
  filters: SensitiveDataFilters,
  groupBy: MetricDimension,
) {
  return useQuery<unknown>({
    queryKey: breakdownKey(filters, groupBy),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/breakdown',
        await api.GET('/api/v1/sensitive-data/breakdown', {
          params: { query: { ...filterQuery(filters), group_by: groupBy } },
        }),
      ),
    retry: false,
  })
}

export const eventsKey = (filters: SensitiveDataFilters, limit: number) =>
  ['sensitive-data', 'events', limit, filterCacheKey(filters)] as const

export function useSensitiveDataEventsQuery(
  filters: SensitiveDataFilters,
  limit: number = EVENT_PAGE_SIZE,
) {
  return useQuery<unknown>({
    queryKey: eventsKey(filters, limit),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/events',
        await api.GET('/api/v1/sensitive-data/events', {
          params: { query: { ...filterQuery(filters), limit } },
        }),
      ),
    retry: false,
  })
}

export const eventDetailKey = (filters: SensitiveDataFilters, eventId: string) =>
  ['sensitive-data', 'event', eventId, filterCacheKey(filters)] as const

/**
 * One event and its findings.
 *
 * The window travels with the lookup because the API scopes the search to it:
 * an id outside the caller's tenant *and window* is a `404`, which is the
 * correct answer — that the id exists somewhere else is not something to
 * disclose.
 */
export function useSensitiveDataEventQuery(filters: SensitiveDataFilters, eventId: string | null) {
  return useQuery<unknown>({
    queryKey: eventDetailKey(filters, eventId ?? ''),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/events/{event_id}',
        await api.GET('/api/v1/sensitive-data/events/{event_id}', {
          params: { path: { event_id: eventId ?? '' }, query: filterQuery(filters) },
        }),
      ),
    enabled: eventId !== null,
    retry: false,
  })
}

export const topOffendersKey = (filters: SensitiveDataFilters, dimension: OffenderDimension) =>
  ['sensitive-data', 'top-offenders', dimension, filterCacheKey(filters)] as const

export function useSensitiveDataTopOffendersQuery(
  filters: SensitiveDataFilters,
  dimension: OffenderDimension,
) {
  return useQuery<unknown>({
    queryKey: topOffendersKey(filters, dimension),
    queryFn: async () =>
      unwrap(
        '/api/v1/sensitive-data/top-offenders',
        await api.GET('/api/v1/sensitive-data/top-offenders', {
          params: { query: { ...filterQuery(filters), dimension } },
        }),
      ),
    retry: false,
  })
}

// ---------------------------------------------------------------------------
// Folds
// ---------------------------------------------------------------------------

function fold<T>(outcome: QueryOutcome<unknown>, decode: Decoder<T>): Certain<T> {
  // `unconfigured` rather than the default `unknown` for an empty body: these
  // routes always carry a scope envelope, so a 200 with nothing in it means the
  // deployment answered without a projection behind it.
  return certainFromShapedQuery(outcome, decode, { whenEmpty: 'unconfigured' })
}

export const summaryFromQuery = (o: QueryOutcome<unknown>): Certain<SensitiveDataSummaryResponse> =>
  fold(o, decodeSummary)

export const timeseriesFromQuery = (
  o: QueryOutcome<unknown>,
): Certain<SensitiveDataTimeseriesResponse> => fold(o, decodeTimeseries)

export const breakdownFromQuery = (
  o: QueryOutcome<unknown>,
): Certain<SensitiveDataBreakdownResponse> => fold(o, decodeBreakdown)

export const eventsFromQuery = (o: QueryOutcome<unknown>): Certain<SensitiveDataEventsResponse> =>
  fold(o, decodeEvents)

export const eventDetailFromQuery = (
  o: QueryOutcome<unknown>,
): Certain<SensitiveDataEventDetailResponse> => fold(o, decodeEventDetail)

export const topOffendersFromQuery = (o: QueryOutcome<unknown>): Certain<TopOffendersResponse> =>
  fold(o, decodeTopOffenders)

// ---------------------------------------------------------------------------
// The compliance export
// ---------------------------------------------------------------------------

/**
 * Request the compliance export, having been told to.
 *
 * `acknowledge_export` is **required** by this signature rather than defaulted
 * to `true`, so a caller cannot obtain the export without writing the word down.
 * The API refuses anything but `true` with a `400`; sending `false` is therefore
 * a way to *test* the gate, and the parameter exists partly so that test can be
 * written without hand-rolling a fetch.
 *
 * Not a hook and not cached: an export is an access-logged act attributed to a
 * principal, and a cache would let a second component obtain a copy without a
 * second record being written.
 */
export async function requestComplianceExport(
  filters: SensitiveDataFilters,
  acknowledgeExport: boolean,
): Promise<unknown> {
  return unwrap(
    '/api/v1/sensitive-data/export',
    await api.GET('/api/v1/sensitive-data/export', {
      params: { query: { ...filterQuery(filters), acknowledge_export: acknowledgeExport } },
    }),
  )
}
