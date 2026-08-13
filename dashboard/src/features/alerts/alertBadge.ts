// The count behind the nav's CRITICAL alert badge (AAASM-5149).
//
// The shell used to count `severity === 'CRITICAL'` with no status predicate,
// so an alert resolved weeks ago kept a red badge on the nav item forever. The
// predicate lives here, next to the alert types it reasons about, so the shell
// consumes a named, tested selector rather than re-deriving "what counts as an
// open incident" inline.
//
// The shell's own wiring (`components/AppShell.tsx`) is owned by a different
// lane and is NOT changed by this ticket. When it is wired, it must consume
// `criticalFiringBadge` and pass a `Certain` built from the query outcome
// (`certainFromQuery`) — NOT `criticalFiringCount(alerts.data ?? [])`. The
// `?? []` form is the fail-open pattern this lane exists to remove: it turns a
// failed alerts request into "0 critical alerts", which the shell renders as no
// badge at all, which reads as "nothing critical is happening".

import { known, propagateAbsence, type Certain } from '../../lib/truthfulness'
import type { Alert } from './types'

/**
 * Alerts that still demand attention.
 *
 * `SUPPRESSED` is excluded alongside `RESOLVED`: a silence is an operator
 * saying "I know, stop telling me", and a badge that keeps shouting through a
 * deliberate silence trains people to ignore the badge.
 */
export function isOpenIncident(alert: Alert): boolean {
  return alert.status === 'FIRING'
}

/** Count of CRITICAL alerts that are currently firing. */
export function criticalFiringCount(alerts: readonly Alert[]): number {
  return alerts.filter((a) => a.severity === 'CRITICAL' && isOpenIncident(a)).length
}

/**
 * The badge count, or the reason there isn't one.
 *
 * Returns an absence rather than `0` when the alerts list could not be loaded:
 * a nav item with no badge reads as "nothing critical is happening", which is
 * precisely the claim a failed request does not entitle the shell to make.
 * `0` from a *successful* query is a real answer and stays a real answer.
 */
export function criticalFiringBadge(alerts: Certain<readonly Alert[]>): Certain<number> {
  if (!alerts.known) return propagateAbsence(alerts)
  return known(criticalFiringCount(alerts.value))
}
