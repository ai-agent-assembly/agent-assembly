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

/**
 * Name the subsystems a degraded `checks` map is complaining about.
 *
 * The health endpoint answers 503 with a full `HealthResponse`, so the operator
 * can be told *what* is down instead of just that something is. Anything that
 * is not a recognisable checks map yields `undefined` and the caller falls back
 * to the bare status code — a wrong guess about the body would be its own small
 * fabrication.
 */
function describeDegradedChecks(body: unknown): string | undefined {
  if (typeof body !== 'object' || body === null) return undefined
  const checks = (body as { checks?: unknown }).checks
  if (typeof checks !== 'object' || checks === null) return undefined
  const degraded = Object.entries(checks as Record<string, unknown>)
    .filter(([, value]) => value !== 'ok')
    .map(([name]) => name)
  return degraded.length > 0 ? degraded.join(', ') : undefined
}

/**
 * Ask the gateway whether it is up, once, on operator demand.
 *
 * Deliberately a one-shot function rather than a query hook: this is an action
 * the operator triggers and whose *outcome* — including the failure — is the
 * thing being reported. It never throws; a rejected `fetch` (the gateway-down
 * case, and the whole reason the ticket is release-blocking) comes back as an
 * error outcome so the caller has no way to render it as a success.
 */
export async function probeGatewayHealth(): Promise<QueryOutcome<GatewayHealth>> {
  try {
    const { data, error, response } = await api.GET('/api/v1/health')
    if (response.ok && error === undefined) {
      return { data: data ?? null }
    }
    const degraded = describeDegradedChecks(error)
    const detail = degraded ? `HTTP ${response.status} — degraded: ${degraded}` : `HTTP ${response.status}`
    return { isError: true, error: new Error(detail) }
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
