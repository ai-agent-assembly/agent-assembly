/**
 * Posture-summary derivation for the agent-detail Overview (AAASM-5131).
 *
 * The panel used to answer four questions from two unrelated counters on the
 * agent record: `Deny = policy_violations_count`, `Allow = session_count −
 * policy_violations_count`, and a literal `0` for both Narrow and Approval. On
 * the surface an operator opens to investigate *one* agent, "Approval 0" reads
 * as *this agent needs no approvals* and "Narrow 0" as *nothing is narrowed* —
 * an all-clear nothing measured.
 *
 * Two separate defects are fixed here, and they need different remedies:
 *
 * ── 1. Allow / Deny were synthesised from the wrong data ─────────────────────
 *
 * `session_count` counts sessions handled; `policy_violations_count` counts
 * violations recorded. They are different populations over different time
 * windows, so their difference is not a quantity — an agent with 10 sessions and
 * 40 violations would have reported `Allow 0` (the `Math.max(0, …)` clamp), and
 * one with 10 sessions and 4 violations reported `Allow 6` for a number that
 * describes nothing. Both figures *are* answerable, from the capability matrix
 * this page already fetches: the projection emits an `allow` / `deny` / `na`
 * verdict per agent × resource × verb cell, and counting those cells is a
 * measurement rather than an arithmetic coincidence.
 *
 * ── 2. Narrow / Approval are structurally unreachable ───────────────────────
 *
 * They cannot be re-derived, from this data or any other the page can reach.
 * `GET /api/v1/capability/matrix` resolves each cell with `decide()`
 * (`aa-api/src/routes/capability.rs`), which returns only `Allow` or `Deny`;
 * unmodelled verbs become `Na`. The module docs state why: `narrow` and
 * `approval` are products of *other* policy stages — credential scrubbing, and a
 * tool's `requires_approval_if` CEL condition evaluated against a **concrete
 * action** — so they "cannot be read off a static capability set". `aa-api` is
 * consistent with itself: `POST /capability/override` **400s** on `Narrow` or
 * `Approval` because such an override "would put a decision in the grid that no
 * projection can ever produce or restore".
 *
 * Because those two are unreachable *by construction* — not a contingent
 * absence like `flagged`, which becomes a real number the moment one agent
 * carries a boolean — ADR-0026 Decision 2 (Accepted) rejects preserving them:
 * a row permanently reading an absence for a state nothing can emit is the
 * aspirational pattern that decision exists to remove. So this module no longer
 * derives Narrow or Approval at all (the drawer drops both rows to match the
 * Capability page under AAASM-5187), rather than deriving them only to render a
 * measured-looking `0` — the same lie with a citation.
 */

import { cascadeEvidenceOf } from '../../features/capability/summary'
import { VERBS, type CapabilityAgent, type Resource } from '../../features/capability/types'
import {
  absent,
  certainFromQuery,
  isKnown,
  propagateAbsence,
  tallyVerdicts,
  type CapabilityVerdict,
  type Certain,
  type QueryOutcome,
} from '../../lib/truthfulness'
import type { ScopedCapabilityMatrix } from './useAgentCapabilityMatrix'

/**
 * The two posture figures this projection can measure, each either a count or
 * an explicit absence. There is deliberately no `number` anywhere in this type:
 * a consumer cannot render one of these without first narrowing through
 * `isKnown`, which is what stops a fallback zero reaching the screen.
 *
 * Narrow and Approval are absent by construction — no matrix cell can carry
 * either verdict (`decide()` returns only Allow/Deny; unmodelled verbs are
 * `Na`) — so per ADR-0026 Decision 2 they are not carried here at all rather
 * than carried as a permanent absence. `tallyVerdicts` still computes `narrow`
 * as shared vocabulary, so restoring a Narrow row is one destructured name if
 * AAASM-5094 delivers a real Narrow computation.
 */
export interface AgentPosture {
  readonly allow: Certain<number>
  readonly deny: Certain<number>
}

/**
 * Every capability decision the projection makes for this agent.
 *
 * A resource column missing from `agent.caps` is yielded as `na`, not
 * `undefined`, for the reason `summarizeMatrix` gives: `project_matrix` emits a
 * cell for every agent × system-resource pair and, beyond those, only for the
 * tools the agent declared. A gap therefore means *this resource is out of that
 * agent's scope* — `not-supported`, which is legitimately outside the counted
 * population — rather than *nothing evaluated it*, which would disqualify the
 * whole tally and blank a panel we can in fact answer.
 *
 * All four verbs are counted, unlike the org-wide summary row, because this
 * panel has no verb selector: its question is "what does policy say about this
 * agent", not "about this agent's writes".
 */
function* agentCells(
  agent: CapabilityAgent,
  resources: readonly Resource[],
): Generator<CapabilityVerdict | undefined> {
  for (const resource of resources) {
    for (const verb of VERBS) {
      yield agent.caps[resource.id]?.[verb] ?? 'na'
    }
  }
}

/**
 * Derive the posture figures from the scoped capability-matrix query.
 *
 * Takes the query *outcome* rather than calling the hook, so the pending and
 * failed paths are directly testable and so the panel and its unit tests read
 * the same normalisation. Precedence follows `certainFromQuery`: a failed
 * request is `unavailable`, an in-flight one `unknown`, and an empty policy
 * cascade folds Allow/Deny to `unconfigured` via `tallyVerdicts` — because with
 * no policy document loaded `decide()` falls through to `Allow` for every cell,
 * so counting them would report a permissive agent nothing granted.
 */
export function deriveAgentPosture(outcome: QueryOutcome<ScopedCapabilityMatrix>): AgentPosture {
  const matrix = certainFromQuery(outcome)
  if (!isKnown(matrix)) {
    const carried = propagateAbsence<ScopedCapabilityMatrix, number>(matrix)
    return { allow: carried, deny: carried }
  }

  const { agent, resources, policies } = matrix.value
  if (agent === null) {
    // The matrix loaded and this agent is simply not in it — no resource claims
    // have been observed for it. Nothing evaluated its capabilities, so a `0`
    // here would claim a clean grid we never looked at.
    const noRow = absent<number>(
      'not-evaluated',
      'This agent has no row in the capability matrix',
    )
    return { allow: noRow, deny: noRow }
  }

  const tally = tallyVerdicts(agentCells(agent, resources), cascadeEvidenceOf(policies))
  // `tally.narrow` is deliberately discarded: with a loaded cascade it is a
  // perfectly typed `known(0)`, and it is `0` for the structural reason in the
  // module header, not because zero cells were narrowed. There is no Narrow row
  // to carry it into — see the `AgentPosture` type doc.
  return { allow: tally.allow, deny: tally.deny }
}

/**
 * The denominator the bars are drawn against: the size of the population that
 * was actually counted.
 *
 * Only known figures contribute, so an absent row can never widen the scale and
 * shrink the bars of the rows that *are* measured. Floors at 1 so a fully absent
 * or genuinely all-`na` panel divides by a positive number; every bar in that
 * case has no fill anyway.
 */
export function postureScale(posture: AgentPosture): number {
  const total = [posture.allow, posture.deny]
    .filter(isKnown)
    .reduce((sum, figure) => sum + figure.value, 0)
  return Math.max(total, 1)
}
