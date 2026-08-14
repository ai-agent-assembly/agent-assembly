/**
 * Block-level status surface for the truthfulness vocabulary (AAASM-5173).
 *
 * The single implementation behind every "this panel has no value to show"
 * surface. Two competing state families existed before this lane:
 *
 *  - `components/{Empty,Loading,Error}State.tsx` — the faithful port of the
 *    hi-fi `states.jsx` mock, with per-page copy tables;
 *  - `components/states/{Empty,Error}State.tsx` — a generic, prop-driven pair
 *    used by four call sites that bypassed the ported family entirely.
 *
 * They disagreed about roles, tone, and what an absence even is. `StatusState`
 * is the convergence point: the generic pair now delegates here, so there is
 * one accessibility contract and one visual vocabulary. New surfaces should use
 * `StatusState` directly.
 */
import type { ReactNode } from 'react'
import { TRUTH_STATE_META, type TruthState } from '../../lib/truthfulness'
import './truthfulness.css'

export interface StatusStateProps {
  /**
   * Why there is nothing to show — or `null` for a genuinely empty result.
   *
   * `null` is not an absence: "the query succeeded and returned zero rows" is a
   * real, known answer and must not be dressed up as a fault. Everything else
   * is an absence and renders its state badge.
   */
  readonly state: TruthState | null
  readonly title: string
  readonly description?: ReactNode
  /** Operator-facing specifics, e.g. the failing endpoint or a status code. */
  readonly detail?: string
  readonly icon?: ReactNode
  readonly action?: ReactNode
  readonly testId?: string
}

/**
 * Only a failed request is announced assertively.
 *
 * `role="alert"` interrupts the user; reserving it for `unavailable` keeps the
 * interruption meaningful. Every other state — including a fully unevaluated
 * governance grid — is a polite `status`, which is still announced, just not
 * as an emergency.
 */
function roleFor(state: TruthState | null): 'alert' | 'status' {
  return state === 'unavailable' ? 'alert' : 'status'
}

export function StatusState({
  state,
  title,
  description,
  detail,
  icon,
  action,
  testId = 'status-state',
}: Readonly<StatusStateProps>) {
  const meta = state ? TRUTH_STATE_META[state] : null
  const role = roleFor(state)
  const className = state ? `truth-state truth-state--${state}` : 'truth-state truth-state--empty'

  return (
    <div
      className={className}
      role={role}
      data-testid={testId}
      data-truth-state={state ?? 'empty'}
    >
      {icon ? (
        <div className="truth-state__icon" aria-hidden>
          {icon}
        </div>
      ) : null}
      {meta ? (
        <div className={`truth-state__badge truth-tone--${meta.tone}`}>{meta.label}</div>
      ) : null}
      <h2 className="truth-state__title">{title}</h2>
      {description ? <div className="truth-state__description">{description}</div> : null}
      {detail ? <p className="truth-state__detail">{detail}</p> : null}
      {/* The state sentence is announced even when the visible badge is
          skimmed past, so the surface can never sound like a healthy one. */}
      {meta ? <span className="truth-sr-only">{meta.announcement}</span> : null}
      {action ? <div className="truth-state__action">{action}</div> : null}
    </div>
  )
}
