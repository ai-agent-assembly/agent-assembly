import { STATUS_META, type LayerStep } from '../../features/trace/decision'
import './LayerSteps.css'

export interface LayerStepsProps {
  readonly steps: readonly LayerStep[]
}

interface LayerStepRowProps {
  readonly step: LayerStep
  readonly isLast: boolean
}

/**
 * One L0–L3 step: status glyph + connecting rail on the left, label / status /
 * detail on the right (hi-fi `TraceStep`). A muted "backend-gated" note stands
 * in for the per-layer detail the API doesn't expose (trust/DID/policy id),
 * rather than inventing values.
 */
function LayerStepRow({ step, isLast }: LayerStepRowProps) {
  const meta = STATUS_META[step.status]
  return (
    <li className="layer-step" data-testid="layer-step" data-layer={step.id} data-status={step.status}>
      <div className="layer-step__rail">
        <span
          className="layer-step__icon"
          aria-hidden="true"
          style={{ color: meta.colorVar, background: meta.bgVar }}
        >
          {meta.icon}
        </span>
        {!isLast && <span className="layer-step__line" />}
      </div>
      <div className="layer-step__body">
        <div className="layer-step__head">
          <span className="layer-step__label">{step.label}</span>
          <span className="layer-step__status" style={{ color: meta.colorVar }}>
            {step.status}
          </span>
        </div>
        <div className="layer-step__detail">{step.detail}</div>
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
