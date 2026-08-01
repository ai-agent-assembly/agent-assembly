/**
 * What the Scrub surface is allowed to fetch, and what each answer means.
 *
 * ## History
 *
 * The headline "stripped / 24h" counter used to be the sum of twelve fixture
 * constants — it rendered `192` on a fresh install with no traffic at all
 * (AAASM-5112). It became the fleet sum of `scrubbed` from
 * `GET /api/v1/analytics/agent-enforcement?window=24h` (`openapi/v1.yaml:1102`,
 * shipped under AAASM-5084), which counts `CredentialLeakBlocked` audit events —
 * the gateway's record of proto `Decision::REDACT`.
 *
 * For a while that was the page's *only* endpoint. AAASM-5174 then shipped three
 * more, which AAASM-5347 wires up here:
 *
 *  - `GET /api/v1/scrub/patterns` — the effective built-in pattern catalogue.
 *  - `GET /api/v1/scrub/pattern-counts` — per-kind detection counts over a window.
 *  - `GET /api/v1/scrub/posture` — leak posture over a window.
 *
 * Everything still without a route — egress coverage, the governing policy
 * document, the scanner's runtime on/off state, and a leak *rate* — stays an
 * explicit absence; see `posture.ts`.
 *
 * ## What `pattern-counts` counts, and why the wording matters
 *
 * It counts **alerts**, not findings. `AlertStore::record_secret`
 * (`aa-api/src/alerts/mod.rs:195-211`) files one `StoredAlert` per intercepted
 * action, and its `detected_pattern_type` is `SecretAlert::primary_kind()`,
 * which is `kinds.first()` (`aa-gateway/src/alerts.rs:39-41`). The handler then
 * tallies those alerts by that single kind (`aa-api/src/routes/scrub.rs:210-220`).
 * So one action carrying an AWS key and three e-mail addresses adds **one** to
 * `AwsAccessKey` and **nothing** to `EmailAddress`. Callers must label the figure
 * as an event/alert count; presenting it as a per-detector finding count would be
 * a fresh truthfulness defect of exactly the kind AAASM-5112 removed.
 *
 * ## The empty/zero rule, applied consistently
 *
 * Every one of these routes confines its aggregation to the caller's tenant
 * (`windowed_secret_alerts`, `aa-api/src/routes/scrub.rs:180-195`): an admin sees
 * every team, a team-scoped caller sees its own, and a caller with neither admin
 * nor a team scope sees **nothing** — which is a successful `200` carrying an
 * empty tally and a zero posture. An empty answer therefore cannot be read as
 * "nothing was detected", and is reported as `unknown` with that reason, exactly
 * as {@link scrubbed24hFromQuery} already does for its own route. A *populated*
 * answer is self-evidently in scope, so it — including a kind that legitimately
 * contributed no alerts to it — is reported as the real measurement it is.
 */
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import {
  absent,
  certainFromQuery,
  isKnown,
  known,
  propagateAbsence,
  type Certain,
  type QueryOutcome,
} from '../../lib/truthfulness'

export type AgentEnforcementCounts = components['schemas']['AgentEnforcementCounts']

export const SCRUBBED_24H_KEY = ['scrub', 'agent-enforcement', '24h'] as const

export function useScrubbed24hQuery() {
  return useQuery<AgentEnforcementCounts[]>({
    queryKey: SCRUBBED_24H_KEY,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/analytics/agent-enforcement', {
        params: { query: { window: '24h' } },
      })
      // Throw rather than return a fallback: `certainFromQuery` turns the
      // rejection into `unavailable`, and a rejected request must never reach
      // the stat strip as a number.
      if (error || !data) throw new Error('agent-enforcement fetch failed')
      return data
    },
  })
}

/**
 * Fold the per-agent rows into the fleet's 24h redaction count.
 *
 * ## Why `[]` is not zero
 *
 * Not because the route omits agents with no enforcement activity — that
 * omission is what would make `[]` *unambiguous*, since a successful read with
 * no rows would mean zero `PolicyViolation` and zero `CredentialLeakBlocked`
 * tenant-wide. The ambiguity is upstream of the aggregation, in two places that
 * both return `200 []`:
 *
 *  - **A swallowed audit-read failure.** `fetch_window_entries`
 *    (`aa-api/src/routes/analytics.rs:381-388`) ends
 *    `AuditReader::list_windowed(…).await.unwrap_or_default()` at `:386`, so a
 *    reader error becomes an empty entry list rather than a `5xx`. The handler
 *    (`get_agent_enforcement`, `:1081`) then aggregates nothing and returns an
 *    empty array with a success status.
 *  - **A caller with no tenant scope.** `scope_entries` (`:350-358`) returns
 *    `Vec::new()` at `:356` for a non-admin caller whose tenant carries no
 *    `org_id`, so every entry is filtered out before it is counted.
 *
 * In both cases the honest answer is "we do not know", and rendering `0` would
 * put a fabricated all-clear on a security surface during an audit-store outage
 * — recreating from a live endpoint exactly the untruth this ticket removed
 * from a literal.
 *
 * Note the `openapi/v1.yaml:1115` line — *"an agent with neither is omitted, so
 * the dashboard renders `—` rather than a synthetic zero"* — is about a
 * **per-agent row**, not about this fleet sum. It is not the justification here.
 *
 * ## Why the asymmetry is correct
 *
 * A **populated** response is itself evidence that the read succeeded and the
 * caller had scope: neither failure mode above can produce a row. So a
 * populated response whose `scrubbed` values sum to `0` **is** a real zero —
 * some agent was audited, and none of its decisions was a redaction — and is
 * reported as one.
 */
export function scrubbed24hFromQuery(
  outcome: QueryOutcome<AgentEnforcementCounts[]>,
): Certain<number> {
  const rows = certainFromQuery(outcome)
  if (!isKnown(rows)) return propagateAbsence(rows)
  if (rows.value.length === 0) {
    return absent(
      'unknown',
      'The 24h enforcement window came back empty. That is also what a swallowed audit-read failure and a caller with no tenant scope return, so it cannot be read as zero redactions.',
    )
  }
  return known(rows.value.reduce((sum, row) => sum + row.scrubbed, 0))
}

// ---------------------------------------------------------------------------
// The three AAASM-5174 routes (wired by AAASM-5347)
// ---------------------------------------------------------------------------

export type ScrubCatalogueResponse = components['schemas']['ScrubCatalogueResponse']
export type ScrubPatternRow = components['schemas']['ScrubPattern']
export type PatternCountsResponse = components['schemas']['PatternCountsResponse']
export type PostureResponse = components['schemas']['PostureResponse']

/**
 * The window presets both aggregations accept (`ScrubWindowParams`).
 *
 * A closed union rather than `string` so a typo cannot silently fall through to
 * the handler's 7d default and leave the page stating a window it did not ask
 * for. The *stated* window still comes from the response's `window_seconds`, not
 * from this request value — see {@link scrubWindowFromQuery}.
 */
export type ScrubRange = '24h' | '7d' | '30d' | '90d'

export const SCRUB_PATTERNS_KEY = ['scrub', 'patterns'] as const
export const scrubPatternCountsKey = (range: ScrubRange) =>
  ['scrub', 'pattern-counts', range] as const
export const scrubPostureKey = (range: ScrubRange) => ['scrub', 'posture', range] as const

/**
 * The effective built-in pattern catalogue.
 *
 * No `range`: the catalogue is the scanner's compiled-in detector set, which is
 * the same for every caller and every window.
 */
export function useScrubPatternsQuery() {
  return useQuery<ScrubCatalogueResponse>({
    queryKey: SCRUB_PATTERNS_KEY,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scrub/patterns')
      if (error || !data) throw new Error('scrub pattern catalogue fetch failed')
      return data
    },
  })
}

export function useScrubPatternCountsQuery(range: ScrubRange) {
  return useQuery<PatternCountsResponse>({
    queryKey: scrubPatternCountsKey(range),
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scrub/pattern-counts', {
        params: { query: { range } },
      })
      if (error || !data) throw new Error('scrub pattern-counts fetch failed')
      return data
    },
  })
}

export function useScrubPostureQuery(range: ScrubRange) {
  return useQuery<PostureResponse>({
    queryKey: scrubPostureKey(range),
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scrub/posture', {
        params: { query: { range } },
      })
      if (error || !data) throw new Error('scrub posture fetch failed')
      return data
    },
  })
}

/** The shared "an empty answer is also what a scopeless caller gets" reason. */
const TENANT_SCOPE_AMBIGUITY =
  'A caller confined to no team sees an empty, all-zero window too, so this cannot be read as "nothing was detected".'

/**
 * The window the *server* aggregated over, in seconds.
 *
 * Deliberately read back off the response rather than echoed from the request:
 * `window_secs_from_range` silently falls back to 7d for a range it cannot
 * parse, so stating the requested range would let the page label a 7-day figure
 * as, say, 30-day. Known as soon as any body arrives — an idle window still has
 * a length.
 */
export function scrubWindowFromQuery(
  outcome: QueryOutcome<{ window_seconds: number }>,
): Certain<number> {
  const body = certainFromQuery(outcome)
  if (!isKnown(body)) return propagateAbsence(body)
  return known(body.value.window_seconds)
}

/**
 * The catalogue rows.
 *
 * An empty `patterns` array is reported as `unknown`, not as "there are no
 * detectors": `CredentialKind::ALL` is a non-empty compile-time constant, so an
 * empty catalogue means something went wrong upstream of the response, never
 * that the gateway ships nothing.
 */
export function scrubCatalogueFromQuery(
  outcome: QueryOutcome<ScrubCatalogueResponse>,
): Certain<readonly ScrubPatternRow[]> {
  const body = certainFromQuery(outcome)
  if (!isKnown(body)) return propagateAbsence(body)
  if (body.value.patterns.length === 0) {
    return absent(
      'unknown',
      'The pattern catalogue came back empty. The gateway’s built-in detector set is never empty, so this is not a report of zero detectors.',
    )
  }
  return known(body.value.patterns)
}

/**
 * A window's per-kind alert tally.
 *
 * `byKind` is keyed by `CredentialKind` string. See the module doc for why these
 * are alert counts rather than finding counts — consumers must label them so.
 */
export interface PatternAlertTally {
  readonly byKind: ReadonlyMap<string, number>
  readonly totalAlerts: number
  readonly windowSeconds: number
}

export function patternAlertsFromQuery(
  outcome: QueryOutcome<PatternCountsResponse>,
): Certain<PatternAlertTally> {
  const body = certainFromQuery(outcome)
  if (!isKnown(body)) return propagateAbsence(body)
  const { counts, total_hits, window_seconds } = body.value
  if (counts.length === 0) {
    return absent('unknown', `No credential kind is tallied in this window. ${TENANT_SCOPE_AMBIGUITY}`)
  }
  return known({
    byKind: new Map(counts.map((c) => [c.kind, c.hits])),
    totalAlerts: total_hits,
    windowSeconds: window_seconds,
  })
}

/**
 * One kind's alert count within a tally.
 *
 * A kind missing from a **populated** tally really did contribute no alert in
 * the window — the handler emits a row only for kinds that fired — so `0` here
 * is a measurement, not a default. When the tally itself is absent the absence
 * propagates, so no row can quietly show `0` because a request failed.
 */
export function alertsForKind(
  tally: Certain<PatternAlertTally>,
  kind: string,
): Certain<number> {
  if (!isKnown(tally)) return propagateAbsence(tally)
  return known(tally.value.byKind.get(kind) ?? 0)
}

/** Leak posture as `GET /api/v1/scrub/posture` measures it. */
export interface ScrubPosture {
  /** Payloads the scanner **caught and redacted** in the window. Not escapes. */
  readonly leaksIntercepted: number
  readonly distinctKinds: number
  readonly windowSeconds: number
}

/**
 * The posture figures.
 *
 * `leaks_intercepted: 0` is reported as `unknown` rather than as zero for the
 * same reason an empty tally is: it is exactly what a caller confined to no team
 * receives, and a zero on a DLP surface reads as an all-clear. A non-zero figure
 * is self-evidently in scope and is reported as measured.
 */
export function scrubPostureFromQuery(
  outcome: QueryOutcome<PostureResponse>,
): Certain<ScrubPosture> {
  const body = certainFromQuery(outcome)
  if (!isKnown(body)) return propagateAbsence(body)
  const { leaks_intercepted, distinct_kinds, window_seconds } = body.value
  if (leaks_intercepted === 0) {
    return absent(
      'unknown',
      `The window reports no intercepted leak. ${TENANT_SCOPE_AMBIGUITY}`,
    )
  }
  return known({
    leaksIntercepted: leaks_intercepted,
    distinctKinds: distinct_kinds,
    windowSeconds: window_seconds,
  })
}

/**
 * The leak *rate* — always absent today.
 *
 * The handler sets `rate_computed: false` and omits `leak_rate` because the
 * alert store persists detections but not the total-payloads-scanned
 * denominator (`aa-api/src/routes/scrub.rs:121-151`). The field is read rather
 * than hard-coded so the page starts reporting a rate by itself on the day the
 * denominator lands, instead of silently continuing to say "not supported".
 */
export function leakRateFromQuery(outcome: QueryOutcome<PostureResponse>): Certain<number> {
  const body = certainFromQuery(outcome)
  if (!isKnown(body)) return propagateAbsence(body)
  const { rate_computed, leak_rate } = body.value
  if (!rate_computed || leak_rate === null || leak_rate === undefined) {
    return absent(
      'not-supported',
      'The alert store persists detections but not the total payloads scanned, so a leak rate has no denominator to divide by.',
    )
  }
  return known(leak_rate)
}

/**
 * Human-readable window label, e.g. `24h` / `7d`. Presentation only.
 *
 * Sub-two-day windows read in hours even when they divide into whole days, so
 * the API's `24h` preset renders as `24h` beside the `redactions / 24h` figure
 * rather than as an equal-but-differently-spelled `1d`. Two labels for one
 * window invite an operator to read them as two different windows.
 */
export function formatWindow(seconds: number): string {
  if (seconds % 3_600 === 0 && seconds < 172_800) return `${seconds / 3_600}h`
  if (seconds % 86_400 === 0) return `${seconds / 86_400}d`
  if (seconds % 3_600 === 0) return `${seconds / 3_600}h`
  return `${seconds}s`
}
