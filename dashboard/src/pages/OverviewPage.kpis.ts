import type { FleetAgent } from '../features/agents/fleetTypes'
import type { Alert } from '../features/alerts/types'
import { absent, isKnown, known, propagateAbsence, type Certain } from '../lib/truthfulness'

/**
 * Pure KPI derivation for the Overview page, kept in a plain module (not the
 * component file) so it can be unit-tested directly and so `OverviewPage.tsx`
 * stays a components-only module (react-refresh `only-export-components`).
 *
 * Every figure this module cannot compute from live data is returned as a
 * `Certain` absence rather than a number. That is the point of the module after
 * AAASM-5113/5114: the previous revision shipped `const scrubScore = 91` — a
 * literal lifted from the design mock — and summed `?? 0` over metrics the
 * fleet contract deliberately types `null`, so an unreported or failed metric
 * reached the operator as a clean bill of health.
 */

/** Severity ordering used to pick the single most-urgent firing alert. */
const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 } as const

/** Sort comparator: most-severe alert first. */
export function compareBySeverity(a: Alert, b: Alert): number {
  return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
}

export interface OverviewKpis {
  readonly total: number
  readonly flagged: number
  readonly enforcing: number
  readonly shadow: number
  /** Absent whenever any agent's count is unreported — see {@link sumEnforcement}. */
  readonly blocked: Certain<number>
  readonly scrubbed: Certain<number>
  /** Absent when the alerts query failed or is still in flight. */
  readonly firingAlerts: Certain<readonly Alert[]>
  readonly identityScore: Certain<number>
  readonly capabilityScore: Certain<number>
  readonly scrubScore: Certain<number>
  readonly overallScore: Certain<number>
}

/**
 * Why the L3 posture ring has no number.
 *
 * No backend metric and no signed-off formula stands behind a "scrub posture
 * score". The previous revision papered over that with the design mock's
 * placeholder `91`, which never moved and was averaged into the overall ring.
 * Whether the posture rings get a ratified derivation at all is ADR 0026
 * Decision 1, still `Proposed` — so this module reports the absence rather than
 * replacing one invented formula with another.
 */
const NO_SCRUB_DERIVATION =
  'No signed-off derivation exists for a scrub posture score (ADR 0026, Decision 1)'

/** Why a score is withheld when the fleet is empty. */
const NO_AGENTS_TO_SCORE = 'No agents are registered, so there is nothing to score'

/**
 * Total one enforcement metric across the fleet, or report that it is unknown.
 *
 * `blocked24h` / `scrubbed24h` are `number | null` by deliberate contract
 * (`fleetTypes.ts`): an agent missing from the per-agent enforcement lookup —
 * which is every agent while that query is loading or errored — carries `null`,
 * and the Fleet table renders `—` for it. A sum is a measurement only if it
 * covers the whole population it claims to describe, so a single unreported
 * agent disqualifies the total instead of being silently counted as zero.
 * Overview previously used `?? 0` here and so contradicted Fleet from the same
 * source data.
 */
export function sumEnforcement(
  fleet: readonly FleetAgent[],
  pick: (agent: FleetAgent) => number | null,
  enforcement: Certain<unknown>,
): Certain<number> {
  if (!isKnown(enforcement)) return propagateAbsence(enforcement)

  let sum = 0
  let unreported = 0
  for (const agent of fleet) {
    const value = pick(agent)
    if (value === null) unreported += 1
    else sum += value
  }
  if (unreported > 0) {
    return absent(
      'unknown',
      `${unreported} of ${fleet.length} agents reported no enforcement counts for this window`,
    )
  }
  return known(sum)
}

/**
 * Arithmetic mean of the layer scores that have a derivation.
 *
 * Unweighted, and named as such at the call site — this expression is what the
 * overall ring's `sublabel="weighted across all layers"` used to describe. Any
 * absent input disqualifies the mean rather than being quietly dropped:
 * averaging over a subset while presenting the result as an overall figure is
 * the same fabrication in a smaller font.
 */
export function meanScore(scores: readonly Certain<number>[]): Certain<number> {
  if (scores.length === 0) {
    return absent('not-evaluated', 'No layer score is available to average')
  }
  let sum = 0
  for (const score of scores) {
    if (!isKnown(score)) return propagateAbsence(score)
    sum += score.value
  }
  return known(Math.round(sum / scores.length))
}

/** The most-severe alert, or `undefined` when the collection is empty. */
export function pickTopAlert(alerts: readonly Alert[]): Alert | undefined {
  return [...alerts].sort(compareBySeverity)[0]
}

/**
 * Project the live query results onto the scalar KPIs the page renders.
 *
 * `fleet` is trusted because the page's guard already turns a loading, failed
 * or empty agents query into a state screen — nothing downstream of the guard
 * sees a fabricated fleet. `enforcement` and `alerts` have no such guard, so
 * they arrive as `Certain` and their absence propagates into every figure
 * derived from them.
 *
 * Identity and capability remain deterministic projections of live counts.
 * They are headline indicators, not the authoritative per-layer audit (that
 * lives on each layer's page), and whether they keep a derivation at all is the
 * open question in ADR 0026 Decision 1 — which this module neither ratifies nor
 * pre-empts.
 */
export function deriveOverviewKpis(
  fleet: readonly FleetAgent[],
  alerts: Certain<readonly Alert[]>,
  enforcement: Certain<unknown>,
): OverviewKpis {
  const total = fleet.length
  const flagged = fleet.filter((a) => a.flagged).length
  const enforcing = fleet.filter((a) => a.mode === 'enforce').length
  const shadow = fleet.filter((a) => a.mode === 'shadow').length

  const blocked = sumEnforcement(fleet, (a) => a.blocked24h, enforcement)
  const scrubbed = sumEnforcement(fleet, (a) => a.scrubbed24h, enforcement)

  const firingAlerts: Certain<readonly Alert[]> = isKnown(alerts)
    ? known(alerts.value.filter((a) => a.status === 'FIRING'))
    : propagateAbsence(alerts)

  // An empty fleet used to score a perfect 100 on both layers. Scoring the
  // posture of nothing is not a clean bill of health, it is the absence of a
  // measurement. The page's guard means this branch is unit-surface only.
  const capabilityScore: Certain<number> =
    total > 0
      ? known(Math.round(100 - (flagged / total) * 100 * 0.5))
      : absent('not-evaluated', NO_AGENTS_TO_SCORE)
  const identityScore: Certain<number> =
    total > 0
      ? known(Math.max(0, 100 - flagged * 3))
      : absent('not-evaluated', NO_AGENTS_TO_SCORE)
  const scrubScore: Certain<number> = absent('not-evaluated', NO_SCRUB_DERIVATION)

  // The scrub layer is excluded rather than folded in: it has no value to
  // contribute, and substituting a constant for it is what corrupted this ring
  // in the first place.
  const overallScore = meanScore([identityScore, capabilityScore])

  return {
    total,
    flagged,
    enforcing,
    shadow,
    blocked,
    scrubbed,
    firingAlerts,
    identityScore,
    capabilityScore,
    scrubScore,
    overallScore,
  }
}
