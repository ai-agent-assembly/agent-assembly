/**
 * The filter state every sensitive-data read shares (AAASM-5360).
 *
 * ## Why there is no organisation selector
 *
 * `SensitiveDataFilterParams` accepts an `org_id`, and the API treats it as a
 * *selection among the orgs the caller may already see* — `resolve_scope` checks
 * it with `AuthenticatedCaller::can_access_org` and answers `403` when it does
 * not hold. A dropdown listing organisations would therefore be a list of
 * guesses: the dashboard has no endpoint that enumerates the orgs a token may
 * read, so anything it offered would either be the caller's own org (a control
 * with one option) or names the caller cannot access (a control that implies an
 * access it does not have). ADR-nothing forbids it; the ticket's requirement
 * does — *"do not build UI that implies a user can select an org they cannot
 * access"* — so no `org_id` is ever sent, and the server reads the org off the
 * verified caller.
 *
 * The consequence is stated rather than hidden: a **cross-tenant** caller (one
 * whose token carries no org) gets a `400` from every endpoint here, because
 * there is no unscoped read to fall back to. `api.ts` classifies that as its own
 * access state with its own copy, instead of rendering an empty chart.
 *
 * ## Why `range` is not counted as a filter
 *
 * Every query has a window; there is no unwindowed read. Counting it would make
 * `activeFilterCount` non-zero for every query and collapse the distinction
 * between *"nothing was recorded in this window"* and *"the filters excluded
 * everything"* — which is one of the three facts this page must keep apart.
 */
import type { operations } from '../../api/generated/schema'

/** The window presets `window_secs_from_range` understands. */
export const SENSITIVE_DATA_RANGES = ['24h', '7d', '30d', '90d'] as const

export type SensitiveDataRange = (typeof SENSITIVE_DATA_RANGES)[number]

/**
 * Every narrowing predicate the surface offers, all optional.
 *
 * The names are the API's own query parameters, deliberately: a rename here
 * would be one more place the two can disagree, and the drill-down columns are
 * already labelled with these words.
 */
export interface SensitiveDataFilters {
  readonly range: SensitiveDataRange
  readonly agent_id?: string
  readonly root_agent_id?: string
  readonly team_id?: string
  readonly tool?: string
  readonly destination?: string
  readonly operation?: string
  readonly outcome?: string
  readonly policy_document_id?: string
  readonly category?: string
  readonly provider?: string
  readonly confidence?: string
  readonly status?: string
  readonly severity?: string
  readonly detection_method?: string
}

/** The narrowing keys, i.e. everything except the window. */
export const FILTER_KEYS = [
  'agent_id',
  'root_agent_id',
  'team_id',
  'tool',
  'destination',
  'operation',
  'outcome',
  'policy_document_id',
  'category',
  'provider',
  'confidence',
  'status',
  'severity',
  'detection_method',
] as const

export type FilterKey = (typeof FILTER_KEYS)[number]

/** How each filter is described in the "N filters active" chip row. */
const FILTER_LABELS = new Map<FilterKey, string>([
  ['agent_id', 'Acting agent'],
  ['root_agent_id', 'Root agent'],
  ['team_id', 'Team'],
  ['tool', 'Tool'],
  ['destination', 'Destination'],
  ['operation', 'Operation'],
  ['outcome', 'Outcome'],
  ['policy_document_id', 'Policy document'],
  ['category', 'Category'],
  ['provider', 'Recognizer'],
  ['confidence', 'Confidence'],
  ['status', 'Triage status'],
  ['severity', 'Severity'],
  ['detection_method', 'Detection method'],
])

export function filterLabel(key: FilterKey): string {
  return FILTER_LABELS.get(key) ?? key
}

/** The window with nothing narrowed. */
export const DEFAULT_FILTERS: SensitiveDataFilters = { range: '7d' }

/**
 * Filters that carry a value.
 *
 * An empty string is not a filter — the API treats a blank the same as absent,
 * and counting one would make "clear this box" leave the page claiming a filter
 * is still narrowing the result.
 */
export function activeFilters(filters: SensitiveDataFilters): FilterKey[] {
  return FILTER_KEYS.filter((key) => {
    const value = filters[key]
    return value !== undefined && value.trim() !== ''
  })
}

export function activeFilterCount(filters: SensitiveDataFilters): number {
  return activeFilters(filters).length
}

/**
 * The shared query every sensitive-data route accepts, from the generated
 * client rather than re-declared here.
 *
 * Taken off `get_summary` because all seven routes take
 * `SensitiveDataFilterParams`; each route's extra parameter (`bucket`,
 * `group_by`, `dimension`, `acknowledge_export`) is spread in at its call site
 * with the literal type the generated client expects.
 */
export type SensitiveDataFilterQuery = NonNullable<
  operations['get_summary']['parameters']['query']
>

/**
 * The query object sent to every sensitive-data route.
 *
 * `org_id` is never a key here — see the module doc. The one cast is at the
 * point of construction and is narrow: the accumulator is keyed by
 * {@link FILTER_KEYS}, every member of which is a parameter name on the
 * generated type, so the assertion cannot introduce a parameter the API does
 * not accept — only fail to include one it does.
 */
export function filterQuery(filters: SensitiveDataFilters): SensitiveDataFilterQuery {
  // Built empty and then filled: an annotated `Record<>` object literal is
  // banned repo-wide (AAASM-5109/5190), and the accumulator form is the
  // sanctioned exception.
  const query: Record<string, string> = {}
  query.range = filters.range
  for (const key of activeFilters(filters)) {
    const value = filters[key]
    if (value !== undefined) query[key] = value.trim()
  }
  return query as SensitiveDataFilterQuery
}

/** A copy with one filter set, or cleared when the value is blank. */
export function withFilter(
  filters: SensitiveDataFilters,
  key: FilterKey,
  value: string,
): SensitiveDataFilters {
  const next = { ...filters }
  if (value.trim() === '') {
    delete next[key]
  } else {
    next[key] = value
  }
  return next
}

/** A copy with every narrowing predicate cleared, keeping the window. */
export function clearFilters(filters: SensitiveDataFilters): SensitiveDataFilters {
  return { range: filters.range }
}

/**
 * A stable cache key for a filter set.
 *
 * `filterQuery` output sorted by key, so two logically equal filter sets share a
 * cache entry however the operator got to them.
 */
export function filterCacheKey(filters: SensitiveDataFilters): string {
  return Object.entries(filterQuery(filters))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${String(value)}`)
    .join('&')
}
