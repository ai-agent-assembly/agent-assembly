/**
 * Access Log data layer.
 *
 * ── Why there is no fetcher here (AAASM-5111) ───────────────────────────────
 *
 * This module used to hold `SEED_ACCESS_LOG`: ten events attributed to named
 * identities (`alice@agent-assembly.dev`, `gateway-ci`) from invented source
 * IPs (`10.0.0.42`, `10.0.0.99`), including **failed** logins. Their timestamps
 * were computed with `isoMinusHours()` against a module-load `new Date()`, so
 * the feed re-based itself on every page load and always looked current. The
 * table was filterable and paginated exactly like a real one. This is the
 * surface an operator opens during an incident review, which makes a fabricated
 * failed login from a fabricated IP the most damaging form of the defect.
 *
 * No endpoint replaces it. `GET /api/v1/logs` — the only audit surface the API
 * exposes — is the per-agent governance log: `LogEntry` carries `agent_id`,
 * `session_id`, `event_type`, `seq`, `timestamp` and an opaque `payload`. It
 * has no human or service **identity**, no **source IP**, no success/failure
 * **result**, and no notion of `login` / `logout` / `member_invite`. Wiring
 * this panel to it would mean synthesising every column the tab is about, which
 * is the defect rather than the fix.
 *
 * So the panel reports `not-supported` and shows nothing. The backend gaps that
 * would make this tab answerable are tracked as **AAASM-5176** (real agent
 * identity issuance — without issued identities there is nothing to attribute
 * an access event *to*) and **AAASM-5177** (API-token expiry lifecycle, which
 * owns the token-rotation events this tab claimed to show).
 *
 * The types below are kept deliberately: they are the contract a future
 * identity-scoped endpoint has to satisfy, and the filter bar is typed against
 * them. What is gone is every value that pretended to be a fact.
 */
import { absent, type AbsentValue } from '../../lib/truthfulness'

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
  /** IPv4 / IPv6 source address. */
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

/**
 * What the dashboard can currently say about identity-attributed access events.
 *
 * `not-supported` rather than `unavailable`: nothing was requested and nothing
 * failed. There is no endpoint to request, so retrying, refreshing, or waiting
 * for a slow response changes nothing — and `unavailable` would tell an
 * operator mid-incident that an audit source exists and is merely down.
 *
 * Exported as a value (not re-derived in the component) so the panel and its
 * tests read the same single statement of the gap.
 */
export const ACCESS_LOG_AVAILABILITY: AbsentValue<readonly AccessLogEvent[]> = absent(
  'not-supported',
  'No endpoint reports identity-attributed access events with a source address',
)
