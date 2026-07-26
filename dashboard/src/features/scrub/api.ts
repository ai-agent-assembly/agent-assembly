/**
 * The one number on the Scrub surface that has a production source (AAASM-5112).
 *
 * The headline "stripped / 24h" counter used to be the sum of twelve fixture
 * constants — it rendered `192` on a fresh install with no traffic at all. It is
 * now the fleet sum of `scrubbed` from
 * `GET /api/v1/analytics/agent-enforcement?window=24h` (`openapi/v1.yaml:1102`,
 * shipped under AAASM-5084), which counts `CredentialLeakBlocked` audit events —
 * the gateway's record of proto `Decision::REDACT`.
 *
 * This is the *only* endpoint the page has. Everything else it wants — a leak
 * posture, per-detector counts, the effective pattern catalogue, egress
 * coverage, the governing policy — has no route in `aa-api` at all and is owned
 * by AAASM-5174; see `posture.ts`.
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
