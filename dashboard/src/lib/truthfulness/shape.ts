/**
 * Shape validation at the render boundary (AAASM-5366).
 *
 * ## The failure this closes
 *
 * A successful `200` whose body does not match the response schema used to be
 * read as if it did. `scrubCatalogueFromQuery` reached straight for
 * `body.patterns.length`, so a body missing `patterns` threw
 * `TypeError: Cannot read properties of undefined (reading 'length')`, the
 * error reached `AppShell`, and the whole page unmounted — a white screen on the
 * product's DLP surface, which tells an operator strictly less than an error
 * state does. `certainFromQuery` cannot prevent that: it is handed a
 * `QueryOutcome<T>` that already *claims* to be a `T`, and the claim is the bug.
 *
 * ## Where the check belongs, and why here
 *
 * Three places were possible:
 *
 *  - **In each fold.** A `patterns == null` guard inside
 *    `scrubCatalogueFromQuery` fixes the reported crash and leaves every sibling
 *    fold — and every fold written next year — one field read away from the same
 *    unmount. Correctness by remembering.
 *  - **In the query function**, throwing on an unreadable body. It would make the
 *    page survive, but it reports the wrong thing: `certainFromQuery` maps a
 *    throw to `unavailable`, "the request for this value failed", and the request
 *    did not fail. It also leaves the folds themselves unsafe for any outcome not
 *    built by that hook.
 *  - **Here**, at the single point where a body enters the truthfulness
 *    vocabulary. The fold receives `QueryOutcome<unknown>` and physically cannot
 *    read a field until it has passed the body through a {@link Decoder}, because
 *    `unknown` has no properties. That is what makes the *next* fold safe without
 *    anyone remembering: not a lint rule, a type error.
 *
 * ## How far that guarantee actually reaches
 *
 * Only as far as the lanes that call *this*. AAASM-5366 converted the folds in
 * `features/scrub/` — the ticket's scope — so on that surface the guarantee is
 * total. Everywhere else `certainFromQuery` is still called with a
 * `QueryOutcome<T>` whose `T` is an unverified wire claim, and the same defect
 * class is live there: `AppShell` filters the policies list, and
 * `features/capability/api.ts` reads `cascadeLoaded`, both without checking the
 * body first. Those are **AAASM-5369**, not this module's to assert. Do not read
 * "a fold cannot read a field before decoding" as a dashboard-wide property
 * until 5369 has moved the remaining lanes over.
 *
 * ## What an unreadable body is reported as
 *
 * `unknown` — we asked, we were answered, and we cannot determine the value —
 * carrying a reason that names the offending field. Deliberately not:
 *
 *  - **`unavailable`**, which asserts the request failed and, on the Scrub page,
 *    routes to a retry affordance. Retrying does not fix a version skew, and the
 *    reason has nowhere to render in a generic error panel.
 *  - **a fabricated value.** There is no `?? 0`, no empty-array fallback, and no
 *    "assume healthy" path anywhere below. An absence stays an absence — an
 *    unmeasured all-clear on a security surface is the untruth AAASM-5112
 *    removed, and re-introducing it here would be strictly worse than the white
 *    screen this module replaces.
 */
import { absent, isKnown, known, propagateAbsence, type Certain, type TruthState } from './absence'
import { certainFromQuery, type QueryOutcome } from './query'

/**
 * The outcome of checking a body against the shape its route declares.
 *
 * `reason` is required on the failing side: a decoder that cannot say *what*
 * was wrong produces an absence the operator cannot act on, which is the
 * difference between this and the white screen only in degree.
 */
export type DecodeResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: string }

/**
 * A total function from an untrusted body to {@link DecodeResult}.
 *
 * Total on purpose — a decoder must not throw, or it re-creates the unmount it
 * exists to prevent, one stack frame further in.
 */
export type Decoder<T> = (body: unknown) => DecodeResult<T>

/** The body matched; `value` is what the rest of the app may read. */
export function conforms<T>(value: T): DecodeResult<T> {
  return { ok: true, value }
}

/** The body did not match. `reason` is shown to the operator verbatim. */
export function violates<T>(reason: string): DecodeResult<T> {
  return { ok: false, reason }
}

export interface ShapedQueryOptions {
  /**
   * State to report when the query succeeded but carried no payload at all.
   *
   * Mirrors `certainFromQuery`'s option of the same name. Note there is no
   * `isDemo`: a demo sample would have to survive decoding to stay renderable,
   * and no caller needs one — offering it would be an untested path on a module
   * whose entire job is to be the trustworthy one.
   */
  readonly whenEmpty?: TruthState
}

/**
 * Normalise a query outcome *and* verify the body before anyone can read it.
 *
 * Precedence is `certainFromQuery`'s, with one step appended: error →
 * `unavailable`, pending → `unknown`, no payload → `whenEmpty`, **body present
 * but unreadable → `unknown` with the decoder's reason**, otherwise known.
 *
 * The parameter is `QueryOutcome<unknown>` rather than `QueryOutcome<T>`: the
 * wire has not yet earned the right to be called a `T`, and accepting one here
 * would let a caller skip the decoder by asserting the type at the hook instead
 * — which is exactly how AAASM-5366 happened.
 */
export function certainFromShapedQuery<T>(
  outcome: QueryOutcome<unknown>,
  decode: Decoder<T>,
  options: ShapedQueryOptions = {},
): Certain<T> {
  const body = certainFromQuery<unknown>(outcome, options)
  if (!isKnown(body)) return propagateAbsence(body)

  const decoded = decode(body.value)
  if (!decoded.ok) return absent<T>('unknown', decoded.reason)
  return known(decoded.value)
}
