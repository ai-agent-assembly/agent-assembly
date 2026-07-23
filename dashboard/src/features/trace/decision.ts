/**
 * Decision-explainer derivation (AAASM-5027).
 *
 * The hi-fi `design/v1/hi-fi/trace.jsx` reframes a trace as an L0–L3
 * *decision explainer*: a verdict (ALLOWED / NARROWED / SCRUBBED / PENDING /
 * DENIED), a per-layer step visual, and a redaction-block payload preview.
 *
 * The live trace API (`/agents/{id}/sessions/{sid}/trace`, still stubbed under
 * AAASM-9) does **not** carry an explicit `decision` field, per-layer detail,
 * a matched-policy id, or a trace_id chain. This module derives everything the
 * current `TraceEvent` shape *can* justify and marks the rest as backend-gated
 * (tracked on AAASM-5029) so the UI never fabricates authority it doesn't have.
 *
 * Derivation is intentionally conservative: only the verdicts the data can
 * actually distinguish (ALLOWED / DENIED / SCRUBBED, plus PENDING when a
 * violation reason names an approval) are ever produced. NARROWED has no
 * current-data signal and is only part of the vocabulary for when the backend
 * lands a real decision field — the chip renders it, the deriver never emits it.
 */

import type { TraceEvent } from './types'

export type Verdict = 'allowed' | 'narrowed' | 'scrubbed' | 'pending' | 'denied'

/**
 * The seven step states from the hi-fi `STATUS_META`. `pending` and `narrow`
 * cannot be produced from current data at the layer level (they need the
 * backend decision field) but are part of the visual vocabulary so the step
 * renderer is complete when those fields land.
 */
export type LayerStatus =
  | 'pass'
  | 'fail'
  | 'pending'
  | 'narrow'
  | 'scrub'
  | 'skip'
  | 'unreached'

export interface VerdictMeta {
  /** Uppercase band/chip label, e.g. `✓ ALLOWED`. */
  readonly label: string
  /** Leading glyph, shown alone on the compact timeline chip. */
  readonly icon: string
  /** Design-token colour var for band border + chip text. */
  readonly colorVar: string
  /** Design-token background var for the chip fill. */
  readonly bgVar: string
}

export const VERDICT_META: Record<Verdict, VerdictMeta> = {
  allowed: { label: '✓ ALLOWED', icon: '✓', colorVar: 'var(--ok)', bgVar: 'var(--ok-bg)' },
  narrowed: { label: '↘ NARROWED', icon: '↘', colorVar: 'var(--warn)', bgVar: 'var(--warn-bg)' },
  scrubbed: { label: '◈ SCRUBBED', icon: '◈', colorVar: 'var(--scrub)', bgVar: 'var(--scrub-bg)' },
  pending: { label: '⏸ PENDING', icon: '⏸', colorVar: 'var(--info)', bgVar: 'var(--info-bg)' },
  denied: { label: '✕ DENIED', icon: '✕', colorVar: 'var(--danger)', bgVar: 'var(--danger-bg)' },
}

export interface StatusMeta {
  readonly icon: string
  readonly colorVar: string
  readonly bgVar: string
}

export const STATUS_META: Record<LayerStatus, StatusMeta> = {
  pass: { icon: '✓', colorVar: 'var(--ok)', bgVar: 'var(--ok-bg)' },
  fail: { icon: '✕', colorVar: 'var(--danger)', bgVar: 'var(--danger-bg)' },
  pending: { icon: '⏸', colorVar: 'var(--info)', bgVar: 'var(--info-bg)' },
  narrow: { icon: '↘', colorVar: 'var(--warn)', bgVar: 'var(--warn-bg)' },
  scrub: { icon: '◈', colorVar: 'var(--scrub)', bgVar: 'var(--scrub-bg)' },
  skip: { icon: '·', colorVar: 'var(--ink-4)', bgVar: 'var(--paper-3)' },
  unreached: { icon: '—', colorVar: 'var(--ink-5)', bgVar: 'var(--paper-3)' },
}

/**
 * Derive the decision verdict from the fields the current API exposes.
 *
 * Precedence (strongest signal first):
 *   1. `redactedFields` present → SCRUBBED (the payload was actually redacted).
 *   2. `credential_leak` type → DENIED (a leak is blocked, not narrowed).
 *   3. `policy_violation` type → PENDING when the reason names an approval,
 *      otherwise DENIED.
 *   4. anything else → ALLOWED (passed through untouched).
 *
 * NARROWED is never emitted: no current field distinguishes a narrowed call
 * from an allowed one. When the backend adds an explicit decision this deriver
 * is the single place to update.
 */
export function deriveVerdict(event: TraceEvent): Verdict {
  if (event.redactedFields && event.redactedFields.length > 0) return 'scrubbed'
  if (event.type === 'credential_leak') return 'denied'
  if (event.type === 'policy_violation') {
    return /\bapprov/i.test(event.violationReason ?? '') ? 'pending' : 'denied'
  }
  return 'allowed'
}

export interface LayerStep {
  /** Stable id, `l0`–`l3`. */
  readonly id: string
  /** Uppercase layer label, e.g. `L2 · CAPABILITY`. */
  readonly label: string
  readonly status: LayerStatus
  /** One-line human detail derived from event fields. */
  readonly detail: string
  /**
   * `true` when the *full* hi-fi detail for this layer needs backend fields the
   * API doesn't expose yet (trust score, DID, matched policy id). Rendered as a
   * muted backend-gated note rather than fabricated.
   */
  readonly backendGated: boolean
}

/**
 * Build the L0–L3 layer steps for one event.
 *
 * Only the L2 status carries decision authority (derived from the verdict);
 * L0/L1 are always `pass` (the request was received and the agent identified),
 * and L3 reflects whether redaction ran, was skipped, or was never reached
 * because the call was blocked earlier.
 */
export function buildLayerSteps(event: TraceEvent): LayerStep[] {
  const verdict = deriveVerdict(event)
  const blockedBeforeScrub = verdict === 'denied' || verdict === 'pending'

  const l2status: LayerStatus =
    verdict === 'denied' ? 'fail' : verdict === 'pending' ? 'pending' : verdict === 'narrowed' ? 'narrow' : 'pass'

  const l3status: LayerStatus = verdict === 'scrubbed' ? 'scrub' : blockedBeforeScrub ? 'unreached' : 'skip'

  const redacted = event.redactedFields ?? []

  return [
    {
      id: 'l0',
      label: 'L0 · REQUEST',
      status: 'pass',
      detail: `${event.type} — ${event.payloadPreview}`,
      backendGated: false,
    },
    {
      id: 'l1',
      label: 'L1 · IDENTITY',
      status: 'pass',
      detail: `agent ${event.agent}`,
      // trust score / DID / framework / owner are not in the trace payload.
      backendGated: true,
    },
    {
      id: 'l2',
      label: 'L2 · CAPABILITY',
      status: l2status,
      detail: event.violationReason ?? 'no policy violation recorded',
      // matched policy id + rule detail (P-0xx) require the backend decision field.
      backendGated: true,
    },
    {
      id: 'l3',
      label: 'L3 · SCRUB',
      status: l3status,
      detail:
        verdict === 'scrubbed'
          ? `redacted: ${redacted.join(', ')}`
          : blockedBeforeScrub
            ? '— not reached (blocked at L2)'
            : 'no redaction applied — pass through',
      backendGated: false,
    },
  ]
}
