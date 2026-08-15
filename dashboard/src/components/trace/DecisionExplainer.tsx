import { useMemo } from 'react'
import type { TraceEvent } from '../../features/trace/types'
import { buildDecisionSteps, deriveVerdict, VERDICT_META } from '../../features/trace/decision'
import { isKnown } from '../../lib/truthfulness'
import { AbsenceMarker, TruthfulValue } from '../truthfulness'
import { DecisionSteps } from './DecisionSteps'
import { RedactionPreview } from './RedactionPreview'
import './DecisionExplainer.css'

export interface DecisionExplainerProps {
  readonly event: TraceEvent
}

/** `${ms} ms total`, applied only to a duration that was actually measured. */
function formatTotal(ms: number): string {
  return `${ms} ms total`
}

/**
 * Decision explainer for one trace event (AAASM-5027) — the hi-fi `trace.jsx`
 * body: an L0–L3 decision-step visual, a decision **outcome band** keyed to the
 * verdict colour, and a redaction-block payload preview.
 *
 * The matched-policy link (`policy P-0xx →`) and the trace_id chain from the
 * hi-fi are backend-gated (no API field yet) and rendered as an explicit note
 * rather than fabricated. Tracked on AAASM-5029.
 *
 * The outcome band is the surface's strongest claim — a full-width coloured
 * verdict — so when no verdict is derivable (AAASM-5109) it renders the neutral
 * absence band instead of a colour. A green ALLOWED band is not a safe default
 * for "we do not know".
 */
export function DecisionExplainer({ event }: DecisionExplainerProps) {
  const verdict = useMemo(() => deriveVerdict(event), [event])
  const steps = useMemo(() => buildDecisionSteps(event), [event])
  const meta = isKnown(verdict) ? VERDICT_META[verdict.value] : null

  return (
    <div
      className="decision-explainer"
      data-testid="decision-explainer"
      data-verdict={isKnown(verdict) ? verdict.value : 'absent'}
    >
      <div className="decision-explainer__eyebrow">decision trace</div>

      <DecisionSteps steps={steps} />

      <div
        className="decision-explainer__band"
        data-testid="decision-outcome-band"
        style={{ borderColor: meta?.colorVar }}
      >
        <span className="decision-explainer__verdict" style={{ color: meta?.colorVar }}>
          {isKnown(verdict) ? (
            VERDICT_META[verdict.value].label
          ) : (
            <AbsenceMarker
              state={verdict.state}
              detail={verdict.detail}
              showLabel
              testId="decision-verdict-absent"
            />
          )}
        </span>
        <span className="decision-explainer__ms">
          <TruthfulValue
            value={event.durationMs}
            format={formatTotal}
            testId="decision-duration"
          />
        </span>
        <span className="decision-explainer__policy" data-testid="decision-policy-gated">
          policy link … backend-gated
        </span>
      </div>

      <RedactionPreview
        payload={event.payload}
        redactedFields={event.redactedFields}
        kind={event.type}
      />

      <p className="decision-explainer__note" data-testid="decision-backend-note">
        trace_id chain and matched-policy detail are backend-gated (AAASM-5029) — shown here as
        &ldquo;…&rdquo; until the trace API exposes the decision fields.
      </p>
    </div>
  )
}
