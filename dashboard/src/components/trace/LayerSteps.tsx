import { STATUS_META, type LayerStatus, type LayerStep } from '../../features/trace/decision'
import { isKnown, type Certain } from '../../lib/truthfulness'
import { AbsenceMarker, TruthfulValue } from '../truthfulness'
import './LayerSteps.css'

export interface LayerStepsProps {
  readonly steps: readonly LayerStep[]
}

interface LayerStepRowProps {
  readonly step: LayerStep
  readonly isLast: boolean
}

/**
 * The rail glyph for one layer.
 *
 * Split out so each branch narrows `status` on its own and neither needs a
 * non-null assertion. An absent status shows the shared absence marker rather
 * than the `unreached` glyph: `unreached` claims the layer was never entered,
 * which is itself a finding, whereas an absence says only that the response
 * reported nothing.
 */
function LayerStatusGlyph({ status }: { readonly status: Certain<LayerStatus> }) {
  if (!isKnown(status)) {
    return (
      <span className="layer-step__icon layer-step__icon--absent">
        <AbsenceMarker
          state={status.state}
          detail={status.detail}
          testId="layer-step-status-absent"
        />
      </span>
    )
  }
  const meta = STATUS_META[status.value]
  return (
    <span
      className="layer-step__icon"
      aria-hidden="true"
      style={{ color: meta.colorVar, background: meta.bgVar }}
    >
      {meta.icon}
    </span>
  )
}

/**
 * One L0–L3 step: status glyph + connecting rail on the left, label / status /
 * detail on the right (hi-fi `TraceStep`). A muted "backend-gated" note stands
 * in for the per-layer detail the API doesn't expose (trust/DID/policy id),
 * rather than inventing values.
 */
function LayerStepRow({ step, isLast }: LayerStepRowProps) {
  const status = step.status
  const meta = isKnown(status) ? STATUS_META[status.value] : null
  return (
    <li
      className="layer-step"
      data-testid="layer-step"
      data-layer={step.id}
      data-status={isKnown(status) ? status.value : 'absent'}
    >
      <div className="layer-step__rail">
        <LayerStatusGlyph status={status} />
        {!isLast && <span className="layer-step__line" />}
      </div>
      <div className="layer-step__body">
        <div className="layer-step__head">
          <span className="layer-step__label">{step.label}</span>
          <span className="layer-step__status" style={{ color: meta?.colorVar }}>
            <TruthfulValue value={step.status} testId="layer-step-status" />
          </span>
        </div>
        <div className="layer-step__detail">
          <TruthfulValue value={step.detail} testId="layer-step-detail" />
        </div>
        {step.backendGated && (
          <div className="layer-step__gated" data-testid="layer-step-gated">
            per-layer detail (trust score · DID · matched policy) … backend-gated (AAASM-5029)
          </div>
        )}
      </div>
    </li>
  )
}

/**
 * L0–L3 layer-step visual for the decision explainer (AAASM-5027). Renders the
 * seven-state status set from `STATUS_META`; the current trace API only lets the
 * deriver produce pass/fail/scrub/skip/unreached, but the renderer covers all
 * seven so it is complete when the backend decision field lands.
 */
export function LayerSteps({ steps }: LayerStepsProps) {
  return (
    <ol className="layer-steps" data-testid="layer-steps">
      {steps.map((step, i) => (
        <LayerStepRow key={step.id} step={step} isLast={i === steps.length - 1} />
      ))}
    </ol>
  )
}
