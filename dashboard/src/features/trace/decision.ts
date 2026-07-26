/**
 * Decision-explainer derivation (AAASM-5027, rewired for the real wire shape by
 * AAASM-5109).
 *
 * The hi-fi `design/v2/hi-fi/trace.jsx` reframes a trace as an L0–L3 *decision
 * explainer*: a verdict (ALLOWED / NARROWED / SCRUBBED / PENDING / DENIED), a
 * per-layer step visual, and a redaction-block payload preview. ADR-0017 items
 * 11–13 ratify the shipped generic `RedactionPreview`, the single `TraceDrawer`
 * container, and this seven-state `LayerSteps` renderer as authoritative over
 * the mock, so none of those are reshaped here.
 *
 * What changed under AAASM-5109 is where a verdict may come from. The previous
 * deriver keyed off `redactedFields`, `violationReason`, and snake_case type
 * names like `policy_violation` — none of which the trace API emits. Against
 * the real `/api/v1/traces/{session_id}` response every one of those tests
 * would miss and the deriver would fall through to its `return 'allowed'`
 * default, stamping a green **✓ ALLOWED** chip on a span that in fact recorded
 * a policy violation. Asserting "allowed" because no field said otherwise is
 * the exact failure the truthfulness vocabulary exists to prevent, so the
 * deriver now returns `Certain<Verdict>` and has no default at all.
 */

import { absent, isKnown, known, type Certain } from '../../lib/truthfulness'
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
 * Verdict words the `decision` field is interpreted for.
 *
 * Deliberately word-only. The audit-reconstruction path builds `decision` as
 * `payload.get("decision").and_then(|v| v.as_i64()).map(|d| d.to_string())` —
 * a *stringified integer* whose encoding is not part of the published schema
 * (`openapi/v1.yaml` types `decision` as a bare nullable string with no enum).
 * Guessing that `"0"` means allowed would be inventing a contract, and getting
 * it backwards would report a denial as a pass, so unrecognised values fall
 * through to an absence instead.
 */
const VERDICT_BY_DECISION: Readonly<Record<string, Verdict>> = {
  allow: 'allowed',
  allowed: 'allowed',
  deny: 'denied',
  denied: 'denied',
  narrow: 'narrowed',
  narrowed: 'narrowed',
  scrub: 'scrubbed',
  scrubbed: 'scrubbed',
  approval: 'pending',
  pending: 'pending',
}

/**
 * Audit event types that are themselves a governance outcome.
 *
 * `operation` is `AuditEventType::as_str()` (`aa-core/src/audit.rs`), so the
 * values are PascalCase names, not the snake_case ones the old deriver matched.
 * Only the variants whose own documentation states the outcome are mapped:
 * `PolicyViolation` is "an evaluated action violated an active policy rule",
 * `CredentialLeakBlocked` and `MessageBlocked` say "blocked", and the three
 * approval variants state granted / denied / requested.
 *
 * Everything else is absent on purpose. `ToolCallIntercepted` — the most common
 * span by far — records only that the governance layer saw the call, never how
 * it ruled, and budget / sandbox / lifecycle events are not per-action verdicts
 * at all. Mapping any of those to ALLOWED would manufacture a pass out of
 * silence.
 */
const VERDICT_BY_OPERATION: Readonly<Record<string, Verdict>> = {
  PolicyViolation: 'denied',
  CredentialLeakBlocked: 'denied',
  MessageBlocked: 'denied',
  ApprovalDenied: 'denied',
  ApprovalGranted: 'allowed',
  ApprovalRequested: 'pending',
  ApprovalRouted: 'pending',
  ApprovalEscalated: 'pending',
}

/**
 * Derive the decision verdict, or say that none is derivable.
 *
 * Precedence: the explicit `decision` field wins when it names a verdict,
 * because it is the field the schema designates for exactly this; otherwise the
 * operation is consulted, since several audit event types *are* the outcome.
 * When neither yields a verdict the result is `not-evaluated` — the surface
 * then renders an absence marker rather than a chip, so a span whose ruling was
 * never recorded is visibly distinct from one that was allowed.
 */
export function deriveVerdict(event: TraceEvent): Certain<Verdict> {
  if (isKnown(event.decision)) {
    const named = VERDICT_BY_DECISION[event.decision.value.trim().toLowerCase()]
    if (named !== undefined) return known(named)
  }

  const byOperation = VERDICT_BY_OPERATION[event.type]
  if (byOperation !== undefined) return known(byOperation)

  return absent<Verdict>(
    'not-evaluated',
    `No governance decision was recorded for a "${event.type}" span`,
  )
}

export interface LayerStep {
  /** Stable id, `l0`–`l3`. */
  readonly id: string
  /** Uppercase layer label, e.g. `L2 · CAPABILITY`. */
  readonly label: string
  /**
   * The step's outcome, or an absence when the wire cannot establish one.
   *
   * Kept as a `Certain<LayerStatus>` rather than widening `LayerStatus` with an
   * eighth "unknown" member, because ADR-0017 item 13 ratifies the seven-state
   * renderer and an unevaluated layer is an absence, not a new kind of outcome.
   */
  readonly status: Certain<LayerStatus>
  /** One-line human detail, or an absence when no field supplies one. */
  readonly detail: Certain<string>
  /**
   * `true` when the *full* hi-fi detail for this layer needs backend fields the
   * API doesn't expose yet (trust score, DID, matched policy id). Rendered as a
   * muted backend-gated note rather than fabricated.
   */
  readonly backendGated: boolean
}

/** How a known verdict colours the L2 capability step. */
const L2_STATUS_BY_VERDICT: Readonly<Record<Verdict, LayerStatus>> = {
  denied: 'fail',
  pending: 'pending',
  narrowed: 'narrow',
  scrubbed: 'pass',
  allowed: 'pass',
}

const REDACTION_NOT_ON_SPAN =
  'TraceSpan has no redaction field, so whether the scrub layer altered this payload was never reported'

/**
 * The L3 scrub status.
 *
 * Only one branch is inferable today. When L2 denied or suspended the call it
 * demonstrably never reached the scrub layer, so `unreached` is a fact. Whether
 * an *allowed* call was scrubbed depends on `redactedFields`, which the span
 * schema has no field for — so the honest answer there is an absence, not the
 * `skip` the old deriver reported. `skip` asserts "redaction ran and found
 * nothing", which is a claim about the scrubber this response cannot support.
 */
function l3Status(verdict: Certain<Verdict>): Certain<LayerStatus> {
  if (isKnown(verdict) && (verdict.value === 'denied' || verdict.value === 'pending')) {
    return known<LayerStatus>('unreached')
  }
  return absent<LayerStatus>('not-supported', REDACTION_NOT_ON_SPAN)
}

/**
 * Build the L0–L3 layer steps for one event.
 *
 * L0 and L1 remain `pass` on evidence rather than by assumption: a span exists,
 * so the request was received, and `TraceResponse.agent_id` names the agent, so
 * identity resolved. L2 follows the verdict — including its absence. L3 is
 * absent for anything the response cannot establish.
 */
export function buildLayerSteps(event: TraceEvent): LayerStep[] {
  const verdict = deriveVerdict(event)

  return [
    {
      id: 'l0',
      label: 'L0 · REQUEST',
      status: known<LayerStatus>('pass'),
      // The operation name is real; the request preview that used to be
      // appended here has no wire source, so it is left to its own absence
      // rather than concatenated into this line as the string "undefined".
      detail: known(event.type),
      backendGated: false,
    },
    {
      id: 'l1',
      label: 'L1 · IDENTITY',
      status: known<LayerStatus>('pass'),
      detail: known(`agent ${event.agent}`),
      // trust score / DID / framework / owner are not in the trace payload.
      backendGated: true,
    },
    {
      id: 'l2',
      label: 'L2 · CAPABILITY',
      status: isKnown(verdict)
        ? known(L2_STATUS_BY_VERDICT[verdict.value])
        : absent<LayerStatus>(verdict.state, verdict.detail),
      // "no policy violation recorded" used to stand in for a missing reason,
      // which reads as an affirmative all-clear. The reason field does not
      // exist on the span, so the absence is reported as such.
      detail: event.violationReason,
      // matched policy id + rule detail (P-0xx) require the backend decision field.
      backendGated: true,
    },
    {
      id: 'l3',
      label: 'L3 · SCRUB',
      status: l3Status(verdict),
      detail: isKnown(event.redactedFields)
        ? known(`redacted: ${event.redactedFields.value.join(', ')}`)
        : absent<string>('not-supported', REDACTION_NOT_ON_SPAN),
      backendGated: false,
    },
  ]
}
