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
  /**
   * The thrown value, if any.
   *
   * `null` is the *absence* of an error, not an error: TanStack Query declares
   * `error: null` on both `QueryObserverSuccessResult` and
   * `QueryObserverPendingResult`, so a healthy result always carries this key.
   * Anything reading it must reject `null` as well as `undefined` — see
   * `hasError`.
   */
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

/**
 * Whether `error` holds an actual thrown value.
 *
 * `null` must be excluded, not just `undefined`: TanStack Query populates
 * `error: null` on every successful *and* pending result, so a bare
 * `!== undefined` check reports a healthy query as a failure — rendering `—`
 * with a fault tone and announcing "the request for this value failed" over a
 * working API. That is the precise harm this module exists to prevent, so the
 * check is factored out and tested against the literal library shapes.
 */
function hasError(error: unknown): boolean {
  return error !== undefined && error !== null
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
 *
 * @deprecated Prefer {@link certainFromShapedQuery} (`./shape`), which takes a
 * `QueryOutcome<unknown>` plus a decoder. This function's `QueryOutcome<T>`
 * carries a `T` the wire has not earned — usually a `data as T` at the fetch
 * boundary — so a fold can read a field off a body that never matched the
 * schema. That is not hypothetical: it threw out of `AppShell`'s render and
 * emptied the document, and it reported an unread capability matrix as a
 * measured zero policy documents (AAASM-5369).
 *
 * Still exported for the eleven modules recorded in
 * `__tests__/foldAudit.test.ts`. Exactly **one** of those modules is recorded
 * safe — `AppShell`, whose alerts query throws in `parseAlertList` before any
 * fold sees the body. The other ten are live defects. (Several individual
 * *folds* inside those ten are safe; the modules are not, and an earlier draft
 * of this note blurred the two.) The deprecation is a signpost for new code;
 * the enforcement is the `no-restricted-imports` allowlist in `.eslintrc.cjs`.
 * Retiring both is AAASM-5380.
 */
export function certainFromQuery<T>(
  outcome: QueryOutcome<T>,
  options: CertainFromQueryOptions = {},
): Certain<T> {
  const { whenEmpty = 'unknown', isDemo = false } = options

  if (outcome.isError === true || hasError(outcome.error)) {
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
