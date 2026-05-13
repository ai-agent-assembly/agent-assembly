import { STEPS } from './fixtures'
import type { StepId, WizardState } from './types'

export function canAdvance(state: WizardState, step: StepId): boolean {
  switch (step) {
    case 'framework':
      return state.framework !== null
    case 'install':
      return state.installVerified
    case 'identity':
      return state.identity !== null
    case 'policy':
      return state.policyPreset !== null
    case 'enroll':
      return state.enrolled
  }
}

export function stepIndex(step: StepId): number {
  return STEPS.findIndex((s) => s.id === step)
}

export function nextStep(step: StepId): StepId | null {
  const i = stepIndex(step)
  if (i < 0 || i >= STEPS.length - 1) return null
  return STEPS[i + 1].id
}

export function prevStep(step: StepId): StepId | null {
  const i = stepIndex(step)
  if (i <= 0) return null
  return STEPS[i - 1].id
}

export function isFinalStep(step: StepId): boolean {
  return stepIndex(step) === STEPS.length - 1
}

export type StepStatus = 'done' | 'current' | 'future'

export function stepStatus(step: StepId, current: StepId): StepStatus {
  const ci = stepIndex(current)
  const si = stepIndex(step)
  if (si < ci) return 'done'
  if (si === ci) return 'current'
  return 'future'
}
