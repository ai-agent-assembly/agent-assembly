/**
 * The count behind the nav rail's Policy badge (AAASM-5369).
 *
 * Extracted out of `components/AppShell.tsx`, where it was an inline
 * `mapCertain(certainFromQuery(policies), list => list.filter(…).length)`. Two
 * reasons, and the first is the defect:
 *
 *  - **It could throw, and a throw there unmounted the application.** The
 *    shell's `ErrorBoundary` wraps `<Outlet />` — the page — not the shell body
 *    that computes this. A `.filter` on a non-array therefore escaped every
 *    boundary in the tree and left `<div id="root">` empty. That is strictly
 *    worse than the single-page white screen AAASM-5366 was raised to fix, and
 *    it happens on every route, because the rail is persistent chrome.
 *  - **An inline fold is invisible to the export sweep.** A named
 *    `*FromQuery` export is enumerable, so
 *    `lib/truthfulness/__tests__/foldAudit.test.ts` can assert this lane stays
 *    decoded without anyone remembering to keep a test in step with the shell.
 *
 * The badge's *semantics* are unchanged and deliberately so — see the caveat
 * inherited from AAASM-5186 below.
 */
import {
  certainFromShapedQuery,
  isKnown,
  known,
  propagateAbsence,
  type Certain,
  type QueryOutcome,
} from '../../lib/truthfulness'
import { decodePolicyActivity } from './schema'

/**
 * How many policy versions the list reports as not in force.
 *
 * AAASM-5186 carried the fail-open out of the shell: `policies.data ?? []`
 * turned a failed or in-flight request into an empty list, counted it to zero,
 * and rendered the zero as an unadorned rail item — a calm, measured Policy
 * entry indistinguishable from "policy is fine". The query outcome is carried
 * through instead, so an outage reaches the DOM as an outage.
 *
 * AAASM-5369 closes the remaining hole in that: a successful `200` whose body
 * is not a policy list. `usePoliciesQuery` only checks `items` for truthiness,
 * so `{ "items": {} }` reached the fold as a non-array and `.filter` threw, and
 * `{ "items": [{}] }` reached it as rows with no `active` key — where
 * `!undefined` is `true`, so every unreadable row counted itself as an inactive
 * policy and the rail showed a confident number derived from nothing. Both are
 * now an explicit absence, which the rail renders as an `AbsenceMarker`.
 *
 * Known caveat, deliberately NOT papered over here — tracked as AAASM-5196: for
 * the admin callers who can reach this endpoint, the count is structurally
 * always 0, because `usePoliciesQuery` sends no `include_archived` and
 * `aa-api`'s `list_policies` then returns only the most-recent version, with
 * `active: true`. Making the number mean something needs a product decision
 * about what the Policy badge should count. That is a separate defect from this
 * fold's shape handling, and is reported rather than silently redefined.
 */
export function inactivePolicyBadgeFromQuery(
  outcome: QueryOutcome<unknown>,
): Certain<number> {
  const rows = certainFromShapedQuery(outcome, decodePolicyActivity)
  if (!isKnown(rows)) return propagateAbsence(rows)
  return known(rows.value.filter((policy) => !policy.active).length)
}
