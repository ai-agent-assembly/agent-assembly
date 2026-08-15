import { STATUS_META, type DecisionStepStatus, type DecisionStep } from '../../features/trace/decision'
import { isKnown, type Certain } from '../../lib/truthfulness'
import { AbsenceMarker, TruthfulValue } from '../truthfulness'
import './DecisionSteps.css'

export interface DecisionStepsProps {
  readonly steps: readonly DecisionStep[]
}

interface DecisionStepRowProps {
  readonly step: DecisionStep
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
function DecisionStepStatusGlyph({ status }: { readonly status: Certain<DecisionStepStatus> }) {
  if (!isKnown(status)) {
    return (
      <span className="decision-step__icon decision-step__icon--absent">
        <AbsenceMarker
          state={status.state}
          detail={status.detail}
          testId="decision-step-status-absent"
        />
      </span>
    )
  }
  const meta = STATUS_META[status.value]
  return (
    <span
      className="decision-step__icon"
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
 * in for the per-step detail the API doesn't expose (trust/DID/policy id),
 * rather than inventing values.
 */
function DecisionStepRow({ step, isLast }: DecisionStepRowProps) {
  const status = step.status
  const meta = isKnown(status) ? STATUS_META[status.value] : null
  return (
    <li
      className="decision-step"
      data-testid="decision-step"
      data-step={step.id}
      data-status={isKnown(status) ? status.value : 'absent'}
    >
      <div className="decision-step__rail">
        <DecisionStepStatusGlyph status={status} />
        {!isLast && <span className="decision-step__line" />}
      </div>
      <div className="decision-step__body">
        <div className="decision-step__head">
          <span className="decision-step__label">{step.label}</span>
          <span className="decision-step__status" style={{ color: meta?.colorVar }}>
            <TruthfulValue value={step.status} testId="decision-step-status" />
          </span>
        </div>
        <div className="decision-step__detail">
          <TruthfulValue value={step.detail} testId="decision-step-detail" />
        </div>
        {step.backendGated && (
          <div className="decision-step__gated" data-testid="decision-step-gated">
            per-step detail (trust score · DID · matched policy) … backend-gated (AAASM-5029)
          </div>
        )}
      </div>
    </li>
  )
}

/**
 * L0–L3 decision-step visual for the decision explainer (AAASM-5027). Renders the
 * seven-state status set from `STATUS_META`; the current trace API only lets the
 * deriver produce pass/fail/scrub/skip/unreached, but the renderer covers all
 * seven so it is complete when the backend decision field lands.
 */
export function DecisionSteps({ steps }: DecisionStepsProps) {
  return (
    <ol className="decision-steps" data-testid="decision-steps">
      {steps.map((step, i) => (
        <DecisionStepRow key={step.id} step={step} isLast={i === steps.length - 1} />
      ))}
    </ol>
  )
}
