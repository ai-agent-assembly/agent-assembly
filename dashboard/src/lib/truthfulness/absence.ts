/**
 * The shared truthfulness vocabulary (AAASM-5173).
 *
 * The design-QA re-audit found the dashboard asserting things it does not know:
 * a failed request rendered as `0`, an absent latency rendered as `<1ms`, an
 * unevaluated capability asserted as `allow`. Each of those is the same
 * bug — an *absence* silently promoted to a legitimate business value.
 *
 * This module defines, once, what the dashboard may say when it does not have a
 * production value. Page-level lanes import this vocabulary; they must not
 * invent a parallel one, because two lanes disagreeing about what "unknown"
 * means is how a governance surface starts lying again.
 *
 * The standing rule this encodes:
 *
 * > Never convert a failed or unavailable request into a legitimate business
 * > value such as 0, healthy, safe, allowed, verified, or successful.
 */

/**
 * The six explicit states a value may be in when it is not a production truth.
 *
 * They are deliberately distinct: collapsing `unavailable` (we asked and the
 * request failed) into `unconfigured` (we asked and there is nothing to
 * configure) would hide an outage behind a setup prompt, and collapsing either
 * into `not-supported` would tell the operator to stop looking.
 */
export type TruthState =
  /** We asked and could not determine the value. */
  | 'unknown'
  /** The request failed; we have no answer at all. */
  | 'unavailable'
  /** The capability exists but nothing is configured for it yet. */
  | 'unconfigured'
  /** No evaluation has been performed, so there is no verdict to report. */
  | 'not-evaluated'
  /** The backend genuinely cannot provide this; waiting will not help. */
  | 'not-supported'
  /** Fixture or demo data — illustrative only, never a production fact. */
  | 'demo'

/** Every state, in escalation order, for exhaustive iteration in tests and docs. */
export const TRUTH_STATES: readonly TruthState[] = [
  'unknown',
  'unavailable',
  'unconfigured',
  'not-evaluated',
  'not-supported',
  'demo',
] as const

/**
 * How urgently a state should read. `fault` means something is broken,
 * `caution` means the operator has an action to take, `neutral` means the
 * absence is expected and benign.
 */
export type TruthTone = 'neutral' | 'caution' | 'fault'

export interface TruthStateMeta {
  /** Short visible label, e.g. shown in a chip or tooltip. */
  readonly label: string
  /**
   * The sentence assistive tech announces in place of the bare `—`.
   *
   * A screen reader must never receive silence or a stray dash where a
   * governance value belongs: the announcement has to make the absence audible,
   * so the surface cannot be mistaken for a clean bill of health.
   */
  readonly announcement: string
  readonly tone: TruthTone
}

export const TRUTH_STATE_META: Record<TruthState, TruthStateMeta> = {
  unknown: {
    label: 'Unknown',
    announcement: 'Unknown — this value could not be determined.',
    tone: 'caution',
  },
  unavailable: {
    label: 'Unavailable',
    announcement: 'Unavailable — the request for this value failed.',
    tone: 'fault',
  },
  unconfigured: {
    label: 'Unconfigured',
    announcement: 'Unconfigured — nothing is configured to produce this value.',
    tone: 'caution',
  },
  'not-evaluated': {
    label: 'Not evaluated',
    announcement: 'Not evaluated — no evaluation has been performed.',
    tone: 'caution',
  },
  'not-supported': {
    label: 'Not supported',
    announcement: 'Not supported — the backend cannot provide this value.',
    tone: 'neutral',
  },
  demo: {
    label: 'Demo data',
    announcement: 'Demo data — illustrative sample, not a production value.',
    tone: 'caution',
  },
}

/**
 * The canonical inline affordance for "no production value here".
 *
 * One glyph, everywhere, so an operator learns to read it once. Never render a
 * bare `0`, `-`, `n/a`, or an empty cell in its place.
 */
export const NO_DATA = '—'

/** A production value the dashboard is entitled to assert. */
export interface KnownValue<T> {
  readonly known: true
  readonly value: T
}

/**
 * The absence of a production value.
 *
 * `sample` exists only for `state: 'demo'`: demo data has something to show but
 * is still not a production truth, so it stays on the `known: false` side of the
 * union. Every `isKnown` guard in the codebase therefore rejects it, and no
 * aggregate can quietly total demo rows into a real number.
 */
export interface AbsentValue<T> {
  readonly known: false
  readonly state: TruthState
  /** Optional operator-facing specifics, e.g. an HTTP status or field name. */
  readonly detail?: string
  /** Illustrative value carried by `demo` only; never a production fact. */
  readonly sample?: T
}

/**
 * A value that is either known, or explicitly and legibly absent.
 *
 * Consumers cannot read `.value` without narrowing through `isKnown`, which is
 * what makes it impossible to pass an absence where a number is expected.
 */
export type Certain<T> = KnownValue<T> | AbsentValue<T>

/** Assert a production value. */
export function known<T>(value: T): Certain<T> {
  return { known: true, value }
}

/** Record an absence with an explicit, displayable reason. */
export function absent<T>(state: TruthState, detail?: string): Certain<T> {
  return { known: false, state, detail }
}

/** Record demo/fixture data: renderable, labelled, and never counted as truth. */
export function demo<T>(sample: T, detail?: string): Certain<T> {
  return { known: false, state: 'demo', detail, sample }
}

export function isKnown<T>(value: Certain<T>): value is KnownValue<T> {
  return value.known
}

export function isAbsent<T>(value: Certain<T>): value is AbsentValue<T> {
  return !value.known
}

/**
 * Lift a possibly-missing value into the vocabulary.
 *
 * `whenMissing` is required: the caller must state *why* the value could be
 * missing, because that is the part a default value would have thrown away.
 * An empty string counts as missing — a blank label is not a fact.
 */
export function certain<T>(
  value: T | null | undefined,
  whenMissing: TruthState,
  detail?: string,
): Certain<T> {
  if (value === null || value === undefined || value === '') {
    return absent<T>(whenMissing, detail)
  }
  return known(value)
}

/**
 * Carry an absence across a change of value type.
 *
 * The reason and detail survive; a `demo` sample does not, because a sample of
 * `T` is not a sample of `U`. Losing the sample is the point — it is better to
 * show `—` than to show a number that illustrates a different quantity.
 */
export function propagateAbsence<T, U>(value: AbsentValue<T>): Certain<U> {
  return { known: false, state: value.state, detail: value.detail }
}

/** Transform a known value; an absence passes through untouched. */
export function mapCertain<T, U>(value: Certain<T>, fn: (inner: T) => U): Certain<U> {
  return isKnown(value) ? known(fn(value.value)) : propagateAbsence(value)
}

/**
 * Render a certain value as display text.
 *
 * Absence always folds to {@link NO_DATA} — including demo data, whose sample is
 * only shown by components that can also render its label. Text has nowhere to
 * put that label, so it declines to show the sample at all.
 */
export function certainText<T>(value: Certain<T>, format?: (inner: T) => string): string {
  if (!isKnown(value)) return NO_DATA
  return format ? format(value.value) : String(value.value)
}
