/**
 * Query-outcome normalisation (AAASM-5173).
 *
 * The one place a fetch/query outcome becomes the truthfulness vocabulary, so a
 * rejected or empty response can never silently become `0`, `healthy`, or
 * `allowed` on the way to a component.
 *
 * The feature hooks under `src/features/*\/api.ts` already do the right thing at
 * the *fetch* boundary — they `throw` on `error` or an empty body rather than
 * returning a fallback. The gap this closes is the *render* boundary: once a
 * hook has thrown, every consumer independently decides what to display, and
 * that is where "render 0" keeps creeping back in. `certainFromQuery` makes the
 * safe choice the shortest one to write.
 *
 * Structural typing on purpose: the parameter shape is a subset of TanStack
 * Query's `UseQueryResult`, so a hook result can be passed straight in, but the
 * helper stays usable from a plain `fetch` wrapper or a test with no query
 * client mounted.
 */

import { absent, demo, known, type Certain, type TruthState } from './absence'

/** The subset of a query result this helper reads. */
export interface QueryOutcome<T> {
  readonly isPending?: boolean
  readonly isError?: boolean
  readonly error?: unknown
  readonly data?: T | null
}

export interface CertainFromQueryOptions {
  /**
   * State to report when the query succeeded but carried no payload.
   *
   * Defaults to `unknown`. Pass `unconfigured` where an empty body genuinely
   * means "nothing is set up yet", or `not-supported` where the endpoint is
   * known never to populate this field.
   */
  readonly whenEmpty?: TruthState
  /**
   * Marks the payload as fixture/demo data so it renders with a visible
   * "Demo data" label and is excluded from every `isKnown` aggregate.
   */
  readonly isDemo?: boolean
}

/** Best-effort operator-facing detail from a thrown value. */
function describeError(error: unknown): string | undefined {
  if (error instanceof Error) return error.message
  if (typeof error === 'string' && error !== '') return error
  return undefined
}

/**
 * Normalise a query outcome into the truthfulness vocabulary.
 *
 * Precedence, strongest disqualifier first:
 *
 *  1. **Error** → `unavailable`. The request failed; there is no value, and the
 *     failure must stay visible rather than degrading to a benign default.
 *  2. **Pending** → `unknown`. We asked and do not yet know. Deliberately not
 *     `unavailable`: a slow request is not a broken one, and rendering a fault
 *     tone while data is in flight trains operators to ignore fault tones.
 *  3. **Empty payload** → `whenEmpty` (default `unknown`). A 200 with no body
 *     answers nothing.
 *  4. Otherwise the value is known — or demo, if `isDemo` was set.
 *
 * Note the `openapi-fetch` gotcha this sits above: the generated client
 * captures `globalThis.fetch` at module load, so a fetch shim installed later
 * is never consulted. Failures therefore have to be intercepted at the network
 * layer (or, in tests, via `page.route`) — not by swapping `fetch` — and this
 * helper only ever sees the outcome, never the transport.
 */
export function certainFromQuery<T>(
  outcome: QueryOutcome<T>,
  options: CertainFromQueryOptions = {},
): Certain<T> {
  const { whenEmpty = 'unknown', isDemo = false } = options

  if (outcome.isError === true || outcome.error !== undefined) {
    return absent<T>('unavailable', describeError(outcome.error))
  }
  if (outcome.isPending === true) {
    return absent<T>('unknown', 'Request in flight')
  }
  if (outcome.data === null || outcome.data === undefined) {
    return absent<T>(whenEmpty, 'Response carried no payload')
  }
  return isDemo ? demo(outcome.data) : known(outcome.data)
}
