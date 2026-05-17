import { useQuery, type UseQueryResult } from '@tanstack/react-query'
import { iamQueryKeys } from './queryKeys'

/**
 * Access Log data layer (AAASM-1398).
 *
 * Until the OpenAPI surface for `/api/v1/audit/...` lands with the
 * identity-scoped filter we need, the panel reads from a process-local
 * seed via the same in-memory + override-seam pattern used by
 * `apiKeys.ts` and `api.ts` (members). Hook signature is built around
 * the eventual server filter so the swap is a one-function change.
 */

export type AccessLogEventType =
  | 'login'
  | 'logout'
  | 'policy_change'
  | 'key_rotate'
  | 'member_invite'
  | 'permission_grant'

export const ACCESS_LOG_EVENT_TYPES: readonly AccessLogEventType[] = [
  'login',
  'logout',
  'policy_change',
  'key_rotate',
  'member_invite',
  'permission_grant',
] as const

export interface AccessLogEvent {
  readonly id: string
  /** ISO-8601 UTC timestamp. */
  readonly timestamp: string
  /** Member email or service-key label that performed the action. */
  readonly identity: string
  readonly event_type: AccessLogEventType
  /** Free-form target description — e.g. `role:service:admin`, `key:gateway-ci`. */
  readonly target: string
  readonly result: 'success' | 'failure'
  /** IPv4 / IPv6 source address; placeholder for v1 seed data. */
  readonly source_ip: string
}

export type AccessLogTimeRange =
  | { readonly kind: '24h' | '7d' | '30d' }
  | { readonly kind: 'custom'; readonly from: string; readonly to: string }

export interface AccessLogFilter {
  readonly identity?: string | null
  readonly eventType?: AccessLogEventType | null
  readonly timeRange?: AccessLogTimeRange
}

// Fixed "now" the seed timestamps are anchored to. The default useQuery call
// applies the time-range filter relative to *real* `Date.now()` at fetch
// time, so seed events stay in-range as long as they're authored close to
// today. The seed below uses live `new Date()` arithmetic at module-load —
// adequate for the dashboard demo seed pattern (mirrors apiKeys.ts).
const NOW = new Date()

function isoMinusHours(hours: number): string {
  return new Date(NOW.getTime() - hours * 60 * 60 * 1000).toISOString()
}

const SEED_ACCESS_LOG: AccessLogEvent[] = [
  {
    id: 'evt-1',
    timestamp: isoMinusHours(1),
    identity: 'alice@example.com',
    event_type: 'login',
    target: 'dashboard',
    result: 'success',
    source_ip: '10.0.0.42',
  },
  {
    id: 'evt-2',
    timestamp: isoMinusHours(3),
    identity: 'alice@example.com',
    event_type: 'policy_change',
    target: 'policy:read-only-baseline',
    result: 'success',
    source_ip: '10.0.0.42',
  },
  {
    id: 'evt-3',
    timestamp: isoMinusHours(6),
    identity: 'gateway-ci',
    event_type: 'key_rotate',
    target: 'key:gateway-ci',
    result: 'success',
    source_ip: '10.0.0.7',
  },
  {
    id: 'evt-4',
    timestamp: isoMinusHours(20),
    identity: 'carol@example.com',
    event_type: 'member_invite',
    target: 'invite:dave@example.com',
    result: 'success',
    source_ip: '10.0.0.51',
  },
  {
    id: 'evt-5',
    timestamp: isoMinusHours(48),
    identity: 'carol@example.com',
    event_type: 'permission_grant',
    target: 'role:service:observer',
    result: 'success',
    source_ip: '10.0.0.51',
  },
  {
    id: 'evt-6',
    timestamp: isoMinusHours(72),
    identity: 'observability-exporter',
    event_type: 'login',
    target: 'gateway',
    result: 'failure',
    source_ip: '10.0.0.99',
  },
  {
    id: 'evt-7',
    timestamp: isoMinusHours(120),
    identity: 'bob@example.com',
    event_type: 'policy_change',
    target: 'policy:admin-baseline',
    result: 'failure',
    source_ip: '10.0.0.8',
  },
  {
    id: 'evt-8',
    timestamp: isoMinusHours(168),
    identity: 'bob@example.com',
    event_type: 'logout',
    target: 'dashboard',
    result: 'success',
    source_ip: '10.0.0.8',
  },
  {
    id: 'evt-9',
    timestamp: isoMinusHours(360),
    identity: 'alice@example.com',
    event_type: 'key_rotate',
    target: 'key:retired-runner',
    result: 'success',
    source_ip: '10.0.0.42',
  },
  {
    id: 'evt-10',
    timestamp: isoMinusHours(720),
    identity: 'retired-runner',
    event_type: 'login',
    target: 'gateway',
    result: 'failure',
    source_ip: '10.0.0.250',
  },
]

interface EventStore {
  events: AccessLogEvent[]
}

const eventStore: EventStore = { events: [...SEED_ACCESS_LOG] }

let _fetchOverride: ((filter: AccessLogFilter) => Promise<AccessLogEvent[]>) | null = null

function timeRangeCutoffIso(range: AccessLogTimeRange | undefined): string | null {
  if (!range) return null
  if (range.kind === '24h') return new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  if (range.kind === '7d') return new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()
  if (range.kind === '30d') return new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
  return null
}

/**
 * In-process filter applied to the seed. Mirrors the eventual server
 * contract: identity exact match, event-type exact match, time-range
 * cutoff (custom = inclusive from/to range, presets = "since N ago").
 */
function applyFilter(events: readonly AccessLogEvent[], filter: AccessLogFilter): AccessLogEvent[] {
  let out = events.slice()
  if (filter.identity) {
    out = out.filter((e) => e.identity === filter.identity)
  }
  if (filter.eventType) {
    out = out.filter((e) => e.event_type === filter.eventType)
  }
  if (filter.timeRange?.kind === 'custom') {
    const { from, to } = filter.timeRange
    out = out.filter((e) => e.timestamp >= from && e.timestamp <= to)
  } else {
    const cutoff = timeRangeCutoffIso(filter.timeRange)
    if (cutoff) out = out.filter((e) => e.timestamp >= cutoff)
  }
  // Newest first — the AC's "paginated table" expects natural reverse-chron order.
  out.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1))
  return out
}

function fetchAccessLog(filter: AccessLogFilter): Promise<AccessLogEvent[]> {
  if (_fetchOverride) return _fetchOverride(filter)
  return Promise.resolve(applyFilter(eventStore.events, filter))
}

export function useAccessLogQuery(
  filter: AccessLogFilter,
): UseQueryResult<AccessLogEvent[]> {
  return useQuery({
    queryKey: iamQueryKeys.accessLog(filter as object),
    queryFn: () => fetchAccessLog(filter),
  })
}

export const _accessLogInternal: {
  reset: () => void
  snapshot: () => readonly AccessLogEvent[]
  setFetchOverride: (
    fn: ((filter: AccessLogFilter) => Promise<AccessLogEvent[]>) | null,
  ) => void
} = {
  reset(): void {
    eventStore.events = [...SEED_ACCESS_LOG]
    _fetchOverride = null
  },
  snapshot(): readonly AccessLogEvent[] {
    return eventStore.events
  },
  setFetchOverride(fn) {
    _fetchOverride = fn
  },
}
