import { useQuery } from '@tanstack/react-query'
import { capabilityClient } from '../../api/capability'
import {
  certainFromShapedQuery,
  isKnown,
  known,
  propagateAbsence,
  type CascadeEvidence,
  type Certain,
  type QueryOutcome,
} from '../../lib/truthfulness'
import { decodeCascadeFields } from './schema'
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
 * Three independent ways the cell verdicts can be untrustworthy, kept apart:
 *
 *  - the request failed or is still in flight — `certainFromShapedQuery` keeps
 *    `certainFromQuery`'s precedence and maps those to `unavailable` /
 *    `unknown`, so a rejected fetch can never reach the summary row as a count;
 *  - the request succeeded and the body is not a capability matrix — the
 *    AAASM-5369 condition, below;
 *  - the request succeeded, the body is readable, and the engine carries no
 *    cascade — the AAASM-5106 condition. The authoritative source for that is
 *    the matrix-level `cascadeLoaded` flag (ADR 0024), not the length of the
 *    `policies` array: a loaded cascade can legitimately carry no
 *    capability-declaring document, so an empty `policies` list is not by
 *    itself proof the cascade is unloaded. When `cascadeLoaded` is `false` the
 *    evidence is a zero `documentCount`, which the verdict rules fold to
 *    `unconfigured`; otherwise the real document count flows through.
 *
 * The parameter is `QueryOutcome<unknown>` rather than
 * `QueryOutcome<CapabilityMatrix>` (AAASM-5369). `api/capability.ts` produces
 * that `CapabilityMatrix` with `data as CapabilityMatrix` — a cast, so the type
 * was a claim about the wire, not a fact about it, and reading `cascadeLoaded`
 * off a body that had none yielded `undefined`. `!undefined` is `true`, so the
 * *third* branch fired on a body nobody could parse and this fold returned
 * `known({ documentCount: 0 })`: a measured zero, which `tallyVerdicts` renders
 * as "no policy document is loaded". Widening to `unknown` means the decoder
 * cannot be skipped — `unknown` has no fields to reach for — so that branch is
 * now only reachable once the flag has actually been read off the wire.
 *
 * Takes the query outcome rather than calling the hook itself so the optimistic
 * matrix the page holds during a bulk override still flows through the same
 * normalisation. That optimistic value is a real `CapabilityMatrix` built
 * client-side and passes the decoder unchanged.
 */
export function cascadeEvidenceFromQuery(
  outcome: QueryOutcome<unknown>,
): Certain<CascadeEvidence> {
  const matrix = certainFromShapedQuery(outcome, decodeCascadeFields)
  if (!isKnown(matrix)) return propagateAbsence(matrix)
  // The engine's own loaded/unavailable signal wins: an unloaded cascade is
  // `unconfigured` even if the projection happened to list a policy row.
  if (!matrix.value.cascadeLoaded) return known({ documentCount: 0 })
  return cascadeEvidenceOf(matrix.value.policies)
}
