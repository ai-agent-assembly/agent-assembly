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
 * An **empty array is not zero**. The route omits any agent that recorded
 * neither a blocked nor a scrubbed decision, so `[]` cannot distinguish "no
 * agent redacted anything" from "nothing is being audited" — `openapi/v1.yaml`
 * says as much on this route: *"an agent with neither is omitted, so the
 * dashboard renders `—` rather than a synthetic zero."* Rendering `0` there
 * would recreate, from a live endpoint, precisely the all-clear this ticket
 * removed from a literal.
 *
 * A populated response that genuinely sums to `0` **is** a real zero and is
 * reported as one: some agent was audited, and none of its decisions was a
 * redaction.
 */
export function scrubbed24hFromQuery(
  outcome: QueryOutcome<AgentEnforcementCounts[]>,
): Certain<number> {
  const rows = certainFromQuery(outcome)
  if (!isKnown(rows)) return propagateAbsence(rows)
  if (rows.value.length === 0) {
    return absent(
      'unknown',
      'No agent recorded a blocked or scrubbed decision in the last 24h; the route omits agents with neither, so this cannot be read as zero redactions.',
    )
  }
  return known(rows.value.reduce((sum, row) => sum + row.scrubbed, 0))
}
