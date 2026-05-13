import { useCallback, useEffect, useState } from 'react'
import { STEPS } from './fixtures'
import { Stepper } from './Stepper'
import { Step1Framework } from './steps/Step1Framework'
import { Step2InstallSdk } from './steps/Step2InstallSdk'
import { Step3IssueIdentity } from './steps/Step3IssueIdentity'
import { Step4BaselinePolicy } from './steps/Step4BaselinePolicy'
import { Step5EnrollAgent } from './steps/Step5EnrollAgent'
import type { StepId, WizardState } from './types'
import { EMPTY_STATE } from './types'
import { canAdvance, isFinalStep, nextStep, prevStep, stepIndex } from './wizardState'
import './OnboardingWizard.css'

export interface OnboardingWizardProps {
  initialStep?: StepId
  initialState?: WizardState
  onFinish: (state: WizardState) => void
  onSkipAll: () => void
  /**
   * Called whenever the current step or wizard state changes — wired by the
   * page to persist the mid-wizard session to localStorage so the user can
   * close the modal and resume at the same step + selections later.
   */
  onPersist?: (snapshot: { step: StepId; state: WizardState }) => void
}

export function OnboardingWizard({
  initialStep = 'framework',
  initialState = EMPTY_STATE,
  onFinish,
  onSkipAll,
  onPersist,
}: OnboardingWizardProps) {
  const [current, setCurrent] = useState<StepId>(initialStep)
  const [state, setState] = useState<WizardState>(initialState)

  useEffect(() => {
    onPersist?.({ step: current, state })
  }, [current, state, onPersist])

  const ready = canAdvance(state, current)
  const ci = stepIndex(current)
  const final = isFinalStep(current)

  const patchState = useCallback(
    (patch: Partial<WizardState>) => setState((prev) => ({ ...prev, ...patch })),
    [],
  )

  const handleContinue = () => {
    if (final) {
      onFinish(state)
      return
    }
    const next = nextStep(current)
    if (next) setCurrent(next)
  }

  const handleSkipStep = () => {
    if (final) {
      onFinish(state)
      return
    }
    const next = nextStep(current)
    if (next) setCurrent(next)
  }

  const handleBack = () => {
    const prev = prevStep(current)
    if (prev) setCurrent(prev)
  }

  return (
    <div className="onb-scrim" data-testid="onboarding-wizard">
      <div
        className="onb-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="onboarding-title"
      >
        <header className="onb-head">
          <div className="onb-head-left">
            <span className="onb-head-mark" aria-hidden>
              ▣
            </span>
            <h1 id="onboarding-title" className="onb-head-title">
              Agent Assembly · setup
            </h1>
            <span className="onb-head-sub" data-testid="onboarding-step-counter">
              step {ci + 1} of {STEPS.length}
            </span>
          </div>
          <button
            type="button"
            className="onb-skip-all"
            data-testid="onboarding-skip-all"
            onClick={onSkipAll}
          >
            skip onboarding ✕
          </button>
        </header>

        <Stepper currentStep={current} onJump={setCurrent} />

        <div className="onb-body">
          {current === 'framework' && (
            <Step1Framework
              state={state}
              onChange={(framework) => patchState({ framework })}
            />
          )}
          {current === 'install' && (
            <Step2InstallSdk
              state={state}
              onVerified={() => patchState({ installVerified: true })}
            />
          )}
          {current === 'identity' && (
            <Step3IssueIdentity
              state={state}
              onIssued={(identity) => patchState({ identity })}
            />
          )}
          {current === 'policy' && (
            <Step4BaselinePolicy
              state={state}
              onChange={(policyPreset) => patchState({ policyPreset })}
            />
          )}
          {current === 'enroll' && (
            <Step5EnrollAgent
              state={state}
              onEnrolled={() => patchState({ enrolled: true })}
            />
          )}
        </div>

        <footer className="onb-foot">
          <span className="onb-foot-meta">
            {ready
              ? '✓ ready to continue'
              : 'complete this step to advance · or skip'}
          </span>
          <div className="onb-foot-actions">
            {ci > 0 && (
              <button
                type="button"
                className="onb-btn"
                data-testid="onboarding-back"
                onClick={handleBack}
              >
                ← back
              </button>
            )}
            <button
              type="button"
              className="onb-btn onb-btn-skip"
              data-testid="onboarding-skip-step"
              onClick={handleSkipStep}
            >
              skip step →
            </button>
            <button
              type="button"
              className="onb-btn onb-btn-primary"
              data-testid="onboarding-continue"
              onClick={handleContinue}
              disabled={!ready}
            >
              {final ? 'finish setup ✓' : 'continue →'}
            </button>
          </div>
        </footer>
      </div>
    </div>
  )
}
