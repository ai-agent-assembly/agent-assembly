// Validating parse for `GET /api/v1/alerts` payloads (AAASM-5149).
//
// This module exists because the boundary above it used to be a lie. The list
// hook read `body.items as readonly Alert[]` — a cast, not a check — and the
// wire does not speak the dashboard's vocabulary:
//
//   wire (aa-api/src/alerts/mod.rs)     dashboard (./types.ts)
//   status:   "unresolved"              AlertStatus: 'FIRING'
//             "resolved"                             'RESOLVED'
//             "suppressed"                           'SUPPRESSED'
//   severity: "info" | "warning"        Severity: 'CRITICAL' | 'HIGH'
//             | "critical"                        | 'MEDIUM'   | 'LOW'
//
// So `a.severity === 'CRITICAL' && a.status === 'FIRING'` could never match a
// real payload. The nav badge therefore counted zero for every live response,
// and a *known* zero renders no badge at all — the rail sat there silently
// asserting "nothing critical is happening" while criticals fired. That is the
// same deception AAASM-5149 was raised to remove, reached through schema drift
// instead of through `?? []`.
//
// The rule this module enforces: an item that cannot be understood must never
// become a well-typed `Alert`. It raises `AlertShapeError`, the hook rejects,
// and `certainFromQuery` renders `unavailable` — the same treatment a failed
// request gets. A payload we cannot read is not an empty fleet.

import type { Alert, AlertStatus, Severity } from './types'

/**
 * Raised when a payload cannot be understood.
 *
 * Deliberately thrown rather than filtered out. Dropping an unreadable row
 * would silently shrink the count — the caller would receive a smaller number
 * with no indication that anything was lost, which is the "confident zero"
 * failure in miniature.
 */
export class AlertShapeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AlertShapeError'
  }
}

/**
 * Lifecycle vocabulary as `aa-api` actually serialises it.
 *
 * Source: `StoredAlert::status` (aa-api/src/alerts/mod.rs:53-57) — `"unresolved"`
 * on capture, `"resolved"` after `AlertStore::resolve`, `"suppressed"` while an
 * active silence covers it (AAASM-1645). The three map 1:1 onto the dashboard's
 * ladder with no judgement call.
 */
const WIRE_STATUS: ReadonlyMap<string, AlertStatus> = new Map([
  ['unresolved', 'FIRING'],
  ['resolved', 'RESOLVED'],
  ['suppressed', 'SUPPRESSED'],
])

/**
 * Severity vocabulary as `aa-api` actually serialises it.
 *
 * Source: `AlertSeverity` + its `Display` impl (aa-api/src/alerts/mod.rs:96-115),
 * which emits `"info" | "warning" | "critical"`.
 *
 * Only `critical → CRITICAL` is load-bearing for this ticket, and it is exact.
 * The other two are an *ordinal alignment* between a three-level backend ladder
 * and a four-level dashboard ladder, not a mapping the product has ratified:
 * `MEDIUM` is unreachable from the current wire, so `warning` lands on `HIGH`
 * and `info` on `LOW`. Flagged in the PR for ratification; if the rule-engine
 * Stories (AAASM-1385…1389) settle on a different ladder, this table is the one
 * place that changes.
 */
const WIRE_SEVERITY: ReadonlyMap<string, Severity> = new Map([
  ['critical', 'CRITICAL'],
  ['warning', 'HIGH'],
  ['info', 'LOW'],
])

/** The dashboard's own vocabulary, accepted unchanged. */
const CANONICAL_STATUS: ReadonlySet<string> = new Set<AlertStatus>([
  'FIRING',
  'RESOLVED',
  'SUPPRESSED',
])
const CANONICAL_SEVERITY: ReadonlySet<string> = new Set<Severity>([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

/**
 * Canonicalise one lifecycle status.
 *
 * Both vocabularies are accepted: the wire speaks the lower-case form today,
 * and the rule-engine Stories are specified in the upper-case form, so the
 * boundary has to survive the transition without a flag day. Anything else
 * throws — guessing at an unrecognised status is how a suppressed alert starts
 * counting as firing.
 */
export function canonicalStatus(raw: unknown): AlertStatus {
  const value = str(raw)
  if (value === null) throw new AlertShapeError('alert.status is not a string')
  if (CANONICAL_STATUS.has(value)) return value as AlertStatus
  const mapped = WIRE_STATUS.get(value.toLowerCase())
  if (mapped) return mapped
  throw new AlertShapeError(`unrecognised alert status: ${JSON.stringify(value)}`)
}

/** Canonicalise one severity. Same contract as {@link canonicalStatus}. */
export function canonicalSeverity(raw: unknown): Severity {
  const value = str(raw)
  if (value === null) throw new AlertShapeError('alert.severity is not a string')
  if (CANONICAL_SEVERITY.has(value)) return value as Severity
  const mapped = WIRE_SEVERITY.get(value.toLowerCase())
  if (mapped) return mapped
  throw new AlertShapeError(`unrecognised alert severity: ${JSON.stringify(value)}`)
}

/**
 * Normalise one alert row.
 *
 * `severity` and `status` are validated, because those two carry the claim the
 * shell makes. The remainder are carried across from whichever spelling the
 * payload uses — the live `AlertResponse` has no rule identity or destination
 * list at all for budget/secret alerts, and those fields resolve to the empty
 * value rather than to something invented. They read blank today (the cast left
 * them `undefined`), so this changes nothing on screen; it just stops the type
 * from claiming they were present.
 */
export function normaliseAlert(raw: unknown): Alert {
  if (!isRecord(raw)) throw new AlertShapeError('alert row is not an object')

  const id = str(raw.id)
  if (id === null) throw new AlertShapeError('alert.id is missing or not a string')

  return {
    id,
    ruleId: str(raw.ruleId) ?? str(raw.rule_id) ?? '',
    ruleName: str(raw.ruleName) ?? str(raw.rule_name) ?? '',
    severity: canonicalSeverity(raw.severity),
    status: canonicalStatus(raw.status),
    agentId: str(raw.agentId) ?? str(raw.agent_id),
    // `timestamp` is when aa-api captured the alert, i.e. when it first fired.
    firstFiredAt: str(raw.firstFiredAt) ?? str(raw.first_fired_at) ?? str(raw.timestamp) ?? '',
    // `updated_at` is the last mutation; it is the resolve time only once the
    // alert is actually resolved, so it is not read for any other status.
    resolvedAt: str(raw.resolvedAt) ?? str(raw.resolved_at) ?? resolvedAtFrom(raw),
    destinationIds: stringArray(raw.destinationIds) ?? stringArray(raw.destination_ids) ?? [],
  }
}

function resolvedAtFrom(raw: Record<string, unknown>): string | null {
  const status = str(raw.status)?.toLowerCase()
  if (status !== 'resolved') return null
  return str(raw.updated_at)
}

function stringArray(value: unknown): readonly string[] | null {
  if (!Array.isArray(value)) return null
  return value.every((v) => typeof v === 'string') ? (value as readonly string[]) : null
}

/**
 * Normalise the `items` array of an alerts envelope.
 *
 * A non-array `items` throws rather than resolving to `[]`. The previous
 * `Array.isArray(body?.items) ? … : []` was the same fail-open as `?? []` one
 * level up: a malformed envelope became an empty fleet, and an empty fleet is a
 * confident claim that nothing is wrong.
 */
export function parseAlertList(items: unknown): readonly Alert[] {
  if (!Array.isArray(items)) {
    throw new AlertShapeError('alerts envelope carried no `items` array')
  }
  return items.map(normaliseAlert)
}
