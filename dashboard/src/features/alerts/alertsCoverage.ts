// How much of the fleet a loaded page actually accounts for (AAASM-5123).
//
// `GET /api/v1/alerts` serves 50 rows by default (100 max) and reports a
// `total` alongside them. Every count the Alerts surface renders is derived
// from the page, not the total, so the surface has to be able to say which of
// the two it is describing — a page count presented as a fleet count is
// truncation dressed up as completeness.

import { isKnown, type Certain } from '../../lib/truthfulness'
import type { Alert } from './types'

/**
 * Does the loaded page account for every alert the server has?
 *
 * `true` only when both numbers are known and the page is not short. An unknown
 * total is not evidence of completeness, so it reads as incomplete — erring
 * toward "these counts may be partial", never toward "these are all of them".
 */
export function coversWholeFleet(
  alerts: Certain<readonly Alert[]>,
  total: Certain<number>,
): boolean {
  if (!isKnown(alerts) || !isKnown(total)) return false
  return alerts.value.length >= total.value
}

/**
 * The sentence that keeps a page count from reading as a fleet count.
 *
 * `null` when there is nothing to qualify: either the page covers everything,
 * or there is no page at all — an absence is already rendered as an absence and
 * does not need a footnote about its scope.
 */
export function statsScopeNote(
  alerts: Certain<readonly Alert[]>,
  total: Certain<number>,
): string | null {
  if (!isKnown(alerts)) return null
  if (coversWholeFleet(alerts, total)) return null
  if (isKnown(total)) {
    return `Counts cover the ${alerts.value.length} alerts on this page, not all ${total.value}.`
  }
  return `Counts cover the ${alerts.value.length} alerts on this page; the server did not report a total.`
}
