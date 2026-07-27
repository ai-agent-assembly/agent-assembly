import {
  absent,
  certain,
  isKnown,
  known,
  propagateAbsence,
  tallyVerdicts,
  type CapabilityVerdict,
  type CascadeEvidence,
  type Certain,
  type VerdictTally,
} from '../../lib/truthfulness'
import type { CapabilityAgent, Resource, Verb } from './types'

/**
 * Aggregate counts for the matrix summary row.
 *
 * Every field is `Certain` (AAASM-5173): a summary count is the single easiest
 * number to fake, because "0 denied" reads as *we evaluated and found no
 * denials* when the truth is often *nothing was ever evaluated*. Consumers must
 * narrow through `isKnown` before rendering, which is what stops an absence
 * reaching the screen as a zero.
 *
 * `VerdictTally`'s `narrow` count is deliberately dropped (AAASM-5187). ADR 0026
 * Decision 2 — Accepted, option (A) — removes `narrow` from every surface of
 * this page "until a real backend computation can produce them", and a summary
 * tile is such a surface. The distinction against `flaggedAgents` is the whole
 * argument: `flagged` is a field the wire contract *has* and nothing populates
 * yet, so its absence is contingent and it becomes a measurement the day one
 * agent carries a boolean. `narrow` is unreachable by construction — `decide()`
 * (`aa-api/src/routes/capability.rs:480-488`) returns only `Allow`/`Deny`, and
 * unmodelled verbs are `Na` — so no cell can ever be counted and the tile could
 * only ever read as an absence. Reporting a permanent absence of an impossible
 * quantity is the aspirational pattern the ADR rejects, not the honest-absence
 * pattern it endorses.
 *
 * `tallyVerdicts` still computes `narrow`; it is the shared vocabulary and other
 * surfaces may legitimately consume it. Re-adding the tile is one destructured
 * name and one `<SummaryStat>` if AAASM-5094 ever computes those cells.
 */
export interface CapabilitySummary extends Omit<VerdictTally, 'narrow'> {
  /** Distinct agents carrying a recent over-permission flag (verb-independent). */
  readonly flaggedAgents: Certain<number>
}

/**
 * Flatten the visible grid into the per-cell decisions for one verb.
 *
 * A missing cell is yielded as `na`, not as `undefined`. That is a statement
 * about this endpoint's contract, not a convenience: `project_matrix` emits a
 * cell for every agent × system-resource pair and, beyond those, only for the
 * tools an agent actually declared. A column present in `resources` but absent
 * from `agent.caps` therefore means *this resource is not in that agent's
 * scope* — which is `na` / not-supported, the same thing the grid itself
 * renders — rather than *nothing evaluated it*.
 *
 * The distinction matters because `tallyVerdicts` disqualifies a whole tally on
 * an unevaluated cell. Leaving these as `undefined` would suppress the summary
 * for any fleet whose agents declare different tools, which is most of them —
 * claiming to know nothing when we know almost everything is its own kind of
 * dishonesty.
 */
function* cellDecisions(
  agents: CapabilityAgent[],
  resources: Resource[],
  verb: Verb,
): Generator<CapabilityVerdict | undefined> {
  for (const agent of agents) {
    for (const resource of resources) {
      yield agent.caps[resource.id]?.[verb] ?? 'na'
    }
  }
}

/**
 * Count the agents the backend has flagged as over-permissioned.
 *
 * `flagged` is absent on every agent in the live projection — nothing in the
 * gateway computes over-permission yet — and an all-absent column means the
 * question was never asked. Reporting `0 flagged agents` there would be a clean
 * bill of health the data cannot support, so it folds to `not-evaluated`. Once
 * a single agent carries a real boolean the column becomes a genuine
 * measurement and the count is asserted normally.
 */
function countFlagged(agents: CapabilityAgent[]): Certain<number> {
  const evaluated = agents.some((agent) => agent.flagged !== undefined)
  if (!evaluated) {
    return absent('not-evaluated', 'No agent carries an over-permission verdict')
  }
  return known(agents.filter((agent) => agent.flagged === true).length)
}

/**
 * Summarise the visible agents × resources grid for one verb.
 *
 * `cascade` carries what the dashboard knows about the policy documents the
 * verdicts were drawn from, and it is the whole point of the signature: with an
 * empty cascade `aa-api`'s `decide()` falls through to `Allow` for every cell
 * (AAASM-5106), so counting those cells would report a fully-permissive fleet
 * that no policy ever granted. `tallyVerdicts` folds that case to
 * `unconfigured` instead — see `lib/truthfulness/verdict.ts` for the rule.
 */
export function summarizeMatrix(
  agents: CapabilityAgent[],
  resources: Resource[],
  verb: Verb,
  cascade: Certain<CascadeEvidence>,
): CapabilitySummary {
  // `narrow` is destructured off rather than spread through: see the note on
  // `CapabilitySummary` for why this page does not report it (AAASM-5187).
  const { allow, deny } = tallyVerdicts(cellDecisions(agents, resources, verb), cascade)
  return {
    allow,
    deny,
    // A cascade the dashboard could not load says nothing about flags either,
    // so only re-derive the flag column when the matrix itself is trustworthy.
    //
    // The absence is propagated rather than relabelled `unavailable`: a pending
    // matrix is `unknown`, and hardcoding a failure here would put "Unavailable
    // — the request failed" next to three stats reading "Unknown", with the
    // self-contradicting tooltip "Unavailable — Request in flight".
    flaggedAgents: isKnown(cascade) ? countFlagged(agents) : propagateAbsence(cascade),
  }
}

/**
 * Describe the policy cascade behind a loaded matrix.
 *
 * `policies` is the set of documents the projection resolved into the cascade;
 * an empty array is the AAASM-5106 condition (nothing loaded), not "no policy
 * applies". `certain` is used rather than a bare length check so an absent
 * policy list stays distinguishable from an empty one — collapsing those two is
 * the same class of bug this lane exists to remove.
 *
 * A missing `policies` key maps to `unknown`, not `unavailable`: this function
 * only ever sees a payload that already arrived, so the request did not fail.
 * `openapi-fetch` performs no runtime validation, so a 200 whose body omits the
 * key is reachable — and the honest answer to that is "we could not determine
 * the cascade", not "the request failed". A genuinely failed request is
 * classified upstream by `cascadeEvidenceFromQuery`.
 */
export function cascadeEvidenceOf(
  policies: readonly unknown[] | null | undefined,
): Certain<CascadeEvidence> {
  const resolved = certain(policies, 'unknown', 'The matrix carried no policy list')
  return isKnown(resolved)
    ? known({ documentCount: resolved.value.length })
    : propagateAbsence(resolved)
}
