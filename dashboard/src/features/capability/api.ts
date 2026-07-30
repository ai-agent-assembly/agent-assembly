import { useQuery } from '@tanstack/react-query'
import { capabilityClient } from '../../api/capability'
import {
  certainFromQuery,
  isKnown,
  known,
  propagateAbsence,
  type CascadeEvidence,
  type Certain,
  type QueryOutcome,
} from '../../lib/truthfulness'
import { cascadeEvidenceOf } from './summary'
import type { CapabilityMatrix } from './types'

/**
 * The live capability matrix backing the Capability page (AAASM-5090).
 *
 * Wraps `GET /api/v1/capability/matrix`, which projects the agent registry and
 * the policy capability cascade. Several columns the view can render — trust
 * score, over-permission flags, per-policy 24h hit counts, call samples — have
 * no source in the gateway yet and arrive absent; consumers must fold those to
 * a `—` placeholder rather than substituting a zero.
 */
export const CAPABILITY_MATRIX_KEY = ['capability', 'matrix'] as const

export function useCapabilityMatrixQuery() {
  return useQuery<CapabilityMatrix>({
    queryKey: CAPABILITY_MATRIX_KEY,
    queryFn: () => capabilityClient.getMatrix(),
  })
}

/**
 * Normalise a matrix query outcome into cascade evidence (AAASM-5173).
 *
 * Two independent ways the cell verdicts can be untrustworthy, kept apart:
 *
 *  - the request failed or is still in flight — `certainFromQuery` maps that to
 *    `unavailable` / `unknown`, so a rejected fetch can never reach the summary
 *    row as a count;
 *  - the request succeeded but the engine carries no cascade — the AAASM-5106
 *    condition. The authoritative source for that is the matrix-level
 *    `cascadeLoaded` flag (ADR 0024), not the length of the `policies` array: a
 *    loaded cascade can legitimately carry no capability-declaring document, so
 *    an empty `policies` list is not by itself proof the cascade is unloaded.
 *    When `cascadeLoaded` is `false` the evidence is a zero `documentCount`,
 *    which the verdict rules fold to `unconfigured`; otherwise the real document
 *    count flows through.
 *
 * Takes the query outcome rather than calling the hook itself so the optimistic
 * matrix the page holds during a bulk override still flows through the same
 * normalisation.
 */
export function cascadeEvidenceFromQuery(
  outcome: QueryOutcome<CapabilityMatrix>,
): Certain<CascadeEvidence> {
  const matrix = certainFromQuery(outcome)
  if (!isKnown(matrix)) return propagateAbsence(matrix)
  // The engine's own loaded/unavailable signal wins: an unloaded cascade is
  // `unconfigured` even if the projection happened to list a policy row.
  if (!matrix.value.cascadeLoaded) return known({ documentCount: 0 })
  return cascadeEvidenceOf(matrix.value.policies)
}
