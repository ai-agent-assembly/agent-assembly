/**
 * The onboarding wizard's only sources of production fact.
 *
 * Before AAASM-5132/5133 the wizard had none: step 2 "verified" the SDK with a
 * 600 ms `setTimeout` and step 5 derived an enrollment count from its own phase
 * variable. Both reported success against a gateway that was never contacted.
 *
 * Everything here therefore returns an *outcome*, never a value with a fallback
 * baked in. Callers hand the outcome to `certainFromQuery` so a failure becomes
 * `unavailable` rather than a benign default — see `src/lib/truthfulness`.
 */
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { components } from '../../api/generated/schema'
import type { QueryOutcome } from '../../lib/truthfulness'

export type GatewayHealth = components['schemas']['HealthResponse']
export type RegisteredAgent = components['schemas']['AgentResponse']

/** What the enroll step polls for: the registry's own count, plus the page. */
export interface RegisteredAgents {
  readonly total: number
  readonly items: readonly RegisteredAgent[]
}

/** Every value in a `checks` map is a status string; anything else is not one. */
function isChecksMap(value: unknown): value is Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false
  return Object.values(value).every((entry) => typeof entry === 'string')
}

/**
 * Recognise a body as a `HealthResponse`, or decline to guess.
 *
 * This is the hinge of the whole 503 path, so it is deliberately strict. The
 * gateway answers a degraded probe with a *complete* HealthResponse — see
 * `aa-api/src/routes/health.rs`, where the 503 and the `"degraded"` status
 * string are derived from the same `all_ok` boolean — so a real degraded answer
 * always carries every field checked here. A reverse proxy's HTML error page or
 * an `aa-api` `ProblemDetail` carries none of them and is correctly declined.
 *
 * Declining matters as much as accepting: reading a health report out of a body
 * that is not one would be a fabrication of exactly the kind this lane removes.
 *
 * The two casts below (AAASM-5217 audit) are accepted-risk: `candidate.checks`
 * (validated as a string-valued map by `isChecksMap`, but not against a
 * closed key set — the gateway's subsystem list is open-ended) is only ever
 * iterated with `Object.entries` in `probeLines.ts`, which reads `[name,
 * status]` pairs and renders both as opaque text; it is never used as an
 * object-lookup key itself. `status` / `version` / `api_version` are likewise
 * rendered as plain text, not indexed into a `Record`.
 */
function asHealthResponse(body: unknown): GatewayHealth | null {
  if (typeof body !== 'object' || body === null) return null
  const candidate = body as Partial<GatewayHealth>
  const shaped =
    typeof candidate.status === 'string' &&
    candidate.status !== '' &&
    typeof candidate.version === 'string' &&
    typeof candidate.api_version === 'string' &&
    isChecksMap(candidate.checks)
  return shaped ? (body as GatewayHealth) : null
}

/**
 * Ask the gateway whether it is up, once, on operator demand.
 *
 * Deliberately a one-shot function rather than a query hook: this is an action
 * the operator triggers and whose *outcome* — including the failure — is the
 * thing being reported. It never throws; a rejected `fetch` (the gateway-down
 * case, and the whole reason the ticket is release-blocking) comes back as an
 * error outcome so the caller has no way to render it as a success.
 *
 * **A 503 is an answer, not a silence.** `health.rs` returns 503 *with* a full
 * HealthResponse naming the failing subsystem in `checks`, so routing every
 * non-2xx to `unavailable` would assert we heard nothing from a gateway that
 * just told us precisely what was broken — the same defect this lane exists to
 * remove, sign-inverted. A recognisable body is therefore returned as data
 * whatever the status code, and the caller reports it as degraded. `isError` is
 * reserved for a genuinely absent answer: a rejected request, or a response
 * whose body is not a health report.
 */
export async function probeGatewayHealth(): Promise<QueryOutcome<GatewayHealth>> {
  try {
    const { data, error, response } = await api.GET('/api/v1/health')
    if (response.ok && error === undefined) {
      return { data: data ?? null }
    }
    const reported = asHealthResponse(error)
    if (reported !== null) {
      return { data: reported }
    }
    return { isError: true, error: new Error(`HTTP ${response.status}`) }
  } catch (cause) {
    return {
      isError: true,
      error: cause instanceof Error ? cause : new Error(String(cause)),
    }
  }
}

/** How often the enroll step re-asks the registry while it is listening. */
export const ENROLLED_AGENTS_POLL_MS = 3000

/**
 * Poll the agent registry while the enroll step is listening.
 *
 * `total` is the registry's own count across all pages, which is the number the
 * step claims; `items` is the first page, used to show *which* agents answered.
 * The query is only enabled while the step is actually watching, so a wizard
 * parked on step 1 does not sit polling the gateway.
 */
export function useRegisteredAgentsQuery(enabled: boolean) {
  return useQuery<RegisteredAgents>({
    queryKey: ['onboarding', 'registered-agents'],
    enabled,
    refetchInterval: enabled ? ENROLLED_AGENTS_POLL_MS : false,
    // The client's default is three retries with exponential backoff, which
    // would leave the step showing "Request in flight" for ~7s after the
    // registry started failing — a poll that already re-asks every 3s gains
    // nothing from that, and the delay is time the operator spends not knowing
    // the read failed. Fail fast; the interval is the retry.
    retry: false,
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/agents', {
        params: { query: { per_page: 100 } },
      })
      if (error) throw new Error('Failed to fetch registered agents')
      // A 200 with no body answers nothing. Coercing it to `total: 0` would be
      // the exact substitution this lane exists to remove: an absent answer
      // rendered as a counted, confirmed zero.
      if (!data) throw new Error('Agent registry returned no payload')
      return { total: data.total, items: data.items }
    },
  })
}
