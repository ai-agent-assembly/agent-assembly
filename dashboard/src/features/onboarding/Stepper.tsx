import { STEPS } from './fixtures'
import type { StepId } from './types'
import { stepIndex, stepStatus } from './wizardState'
import './Stepper.css'

export interface StepperProps {
  currentStep: StepId
  onJump?: (step: StepId) => void
}

export function Stepper({ currentStep, onJump }: StepperProps) {
  const ci = stepIndex(currentStep)
  return (
    <nav
      className="onb-rail"
      aria-label="onboarding progress"
      data-testid="onboarding-stepper"
    >
      {STEPS.map((s, i) => {
        const status = stepStatus(s.id, currentStep)
        const reachable = i <= ci
        return (
          <button
            key={s.id}
            type="button"
            className={`onb-rail-step is-${status}`}
            data-testid={`onboarding-stepper-${s.id}`}
            data-status={status}
            disabled={!reachable}
            aria-current={status === 'current' ? 'step' : undefined}
            onClick={() => reachable && onJump?.(s.id)}
          >
            <span className="onb-rail-num" aria-hidden>
              {status === 'done' ? '✓' : s.num}
            </span>
            <span>{s.label}</span>
          </button>
        )
      })}
    </nav>
  )
}
