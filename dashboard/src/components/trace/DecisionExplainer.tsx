import { useMemo } from 'react'
import type { TraceEvent } from '../../features/trace/types'
import { buildLayerSteps, deriveVerdict, VERDICT_META } from '../../features/trace/decision'
import { LayerSteps } from './LayerSteps'
import { RedactionPreview } from './RedactionPreview'
import './DecisionExplainer.css'

export interface DecisionExplainerProps {
  readonly event: TraceEvent
}

/**
 * Decision explainer for one trace event (AAASM-5027) — the hi-fi `trace.jsx`
 * body: an L0–L3 layer-step visual, a decision **outcome band** keyed to the
 * verdict colour, and a redaction-block payload preview.
 *
 * The matched-policy link (`policy P-0xx →`) and the trace_id chain from the
 * hi-fi are backend-gated (no API field yet) and rendered as an explicit note
 * rather than fabricated. Tracked on AAASM-5029.
 */
export function DecisionExplainer({ event }: DecisionExplainerProps) {
  const verdict = useMemo(() => deriveVerdict(event), [event])
  const steps = useMemo(() => buildLayerSteps(event), [event])
  const meta = VERDICT_META[verdict]

  return (
    <div className="decision-explainer" data-testid="decision-explainer" data-verdict={verdict}>
      <div className="decision-explainer__eyebrow">decision trace</div>

      <LayerSteps steps={steps} />

      <div
        className="decision-explainer__band"
        data-testid="decision-outcome-band"
        style={{ borderColor: meta.colorVar }}
      >
        <span className="decision-explainer__verdict" style={{ color: meta.colorVar }}>
          {meta.label}
        </span>
        <span className="decision-explainer__ms">{event.durationMs}&nbsp;ms total</span>
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
