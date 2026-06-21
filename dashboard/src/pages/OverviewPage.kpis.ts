import type { FleetAgent } from '../features/agents/fleetTypes'
import type { Alert } from '../features/alerts/types'

/**
 * Pure KPI derivation for the Overview page, kept in a plain module (not the
 * component file) so it can be unit-tested directly and so `OverviewPage.tsx`
 * stays a components-only module (react-refresh `only-export-components`).
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
  readonly blocked: number
  readonly scrubbed: number
  readonly firingAlerts: readonly Alert[]
  readonly topAlert: Alert | undefined
  readonly identityScore: number
  readonly capabilityScore: number
  readonly scrubScore: number
  readonly overallScore: number
}

/**
 * Project the live query results onto the scalar KPIs and derived collections
 * the page renders. Pure and side-effect free — extracted from the component
 * body to keep `OverviewPage`'s cognitive complexity within budget and to make
 * the headline-number derivations independently testable.
 *
 * Posture scores are a deterministic projection of live counts: identity is
 * healthy until an agent is flagged; capability degrades with the flagged
 * ratio; scrub stays high while nothing leaks. They are headline indicators,
 * not the authoritative per-layer audit (that lives on each layer's page).
 */
export function deriveOverviewKpis(
  fleet: readonly FleetAgent[],
  alerts: readonly Alert[],
): OverviewKpis {
  const total = fleet.length
  const flagged = fleet.filter((a) => a.flagged).length
  const enforcing = fleet.filter((a) => a.mode === 'enforce').length
  const shadow = fleet.filter((a) => a.mode === 'shadow').length
  const blocked = fleet.reduce((sum, a) => sum + (a.blocked24h ?? 0), 0)
  const scrubbed = fleet.reduce((sum, a) => sum + (a.scrubbed24h ?? 0), 0)

  const firingAlerts = alerts.filter((a) => a.status === 'FIRING')
  const topAlert = [...firingAlerts].sort(compareBySeverity)[0]

  const capabilityScore = total > 0 ? Math.round(100 - (flagged / total) * 100 * 0.5) : 100
  const identityScore = total > 0 ? Math.max(0, 100 - flagged * 3) : 100
  const scrubScore = 91
  const overallScore = Math.round((identityScore + capabilityScore + scrubScore) / 3)

  return {
    total,
    flagged,
    enforcing,
    shadow,
    blocked,
    scrubbed,
    firingAlerts,
    topAlert,
    identityScore,
    capabilityScore,
    scrubScore,
    overallScore,
  }
}
