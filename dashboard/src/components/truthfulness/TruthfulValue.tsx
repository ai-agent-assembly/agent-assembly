/**
 * Inline renderers for the truthfulness vocabulary (AAASM-5173).
 *
 * `TruthfulValue` is the only sanctioned way to put a possibly-absent scalar on
 * screen. It takes a `Certain<T>` rather than `T | undefined`, which is what
 * makes it impossible to hand it a number that is really an absence: there is
 * no overload that accepts a raw value plus a fallback, so the "just render 0"
 * shortcut does not exist.
 */
import type { ReactNode } from 'react'
import {
  NO_DATA,
  TRUTH_STATE_META,
  isKnown,
  type Certain,
  type TruthState,
} from '../../lib/truthfulness'
import './truthfulness.css'

export interface AbsenceMarkerProps {
  readonly state: TruthState
  /** Operator-facing specifics, surfaced in the tooltip alongside the label. */
  readonly detail?: string
  /** Render the uppercase state label next to the glyph, not just on hover. */
  readonly showLabel?: boolean
  readonly testId?: string
}

/**
 * The canonical `—` affordance.
 *
 * The glyph is identical for every state so it stays learnable; the state is
 * carried by colour tone, the `title` tooltip, the `data-truth-state`
 * attribute, and — always — a screen-reader sentence. Assistive tech never
 * receives a bare dash.
 */
export function AbsenceMarker({
  state,
  detail,
  showLabel = false,
  testId = 'truth-absent',
}: Readonly<AbsenceMarkerProps>) {
  const meta = TRUTH_STATE_META[state]
  const title = detail ? `${meta.label} — ${detail}` : meta.label
  return (
    <span
      className={`truth-absent truth-tone--${meta.tone}`}
      data-testid={testId}
      data-truth-state={state}
      title={title}
    >
      <span className="truth-absent__glyph" aria-hidden>
        {NO_DATA}
      </span>
      {showLabel && <span className="truth-absent__label">{meta.label}</span>}
      <span className="truth-sr-only">{detail ? `${meta.announcement} ${detail}.` : meta.announcement}</span>
    </span>
  )
}

export interface TruthfulValueProps<T> {
  /** The value and its provenance. There is deliberately no raw-value form. */
  readonly value: Certain<T>
  /** Presentation for a known value. Defaults to `String(value)`. */
  readonly format?: (inner: T) => ReactNode
  /** Show the state label inline rather than only in the tooltip. */
  readonly showLabel?: boolean
  readonly testId?: string
}

/**
 * Render a value, or render its absence.
 *
 * Demo data is the one absence that still shows something: its sample renders
 * with a permanent "Demo data" badge beside it. Because demo lives on the
 * `known: false` side of `Certain`, no aggregate elsewhere can total it into a
 * production figure — the badge is a display concern, the exclusion is a type
 * concern, and both hold independently.
 */
export function TruthfulValue<T>({
  value,
  format,
  showLabel = false,
  testId = 'truth-value',
}: Readonly<TruthfulValueProps<T>>) {
  if (isKnown(value)) {
    return (
      <span className="truth-value" data-testid={testId} data-truth-state="known">
        {format ? format(value.value) : String(value.value)}
      </span>
    )
  }

  if (value.state === 'demo' && value.sample !== undefined) {
    const meta = TRUTH_STATE_META.demo
    return (
      <span className="truth-value" data-testid={testId} data-truth-state="demo">
        <span className="truth-demo__sample">
          {format ? format(value.sample) : String(value.sample)}
        </span>
        <span className="truth-demo__badge">{meta.label}</span>
        <span className="truth-sr-only">{meta.announcement}</span>
      </span>
    )
  }

  return (
    <AbsenceMarker
      state={value.state}
      detail={value.detail}
      showLabel={showLabel}
      testId={testId}
    />
  )
}
