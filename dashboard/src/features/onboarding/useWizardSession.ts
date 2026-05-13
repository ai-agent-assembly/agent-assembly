import { STEPS } from './fixtures'
import type { StepId, WizardState } from './types'
import { EMPTY_STATE } from './types'

export const ONBOARDING_SESSION_KEY = 'aa.onboarding.session'

export interface WizardSession {
  step: StepId
  state: WizardState
}

const VALID_STEP_IDS = new Set<string>(STEPS.map((s) => s.id))

function isStepId(value: unknown): value is StepId {
  return typeof value === 'string' && VALID_STEP_IDS.has(value)
}

function isWizardState(value: unknown): value is WizardState {
  if (!value || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  return (
    'framework' in v &&
    'installVerified' in v &&
    'identity' in v &&
    'policyPreset' in v &&
    'enrolled' in v
  )
}

/**
 * Reads the persisted mid-wizard session from localStorage. Returns null
 * when nothing is persisted, when the payload is malformed, or when the
 * stored step id is no longer in the STEPS table (e.g. after a wizard
 * shape change).
 */
export function loadWizardSession(
  storage: Storage = window.localStorage,
): WizardSession | null {
  try {
    const raw = storage.getItem(ONBOARDING_SESSION_KEY)
    if (!raw) return null
    const parsed: unknown = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return null
    const v = parsed as Record<string, unknown>
    if (!isStepId(v.step) || !isWizardState(v.state)) return null
    return { step: v.step, state: v.state }
  } catch {
    return null
  }
}

export function saveWizardSession(
  session: WizardSession,
  storage: Storage = window.localStorage,
): void {
  try {
    storage.setItem(ONBOARDING_SESSION_KEY, JSON.stringify(session))
  } catch {
    // ignore (private browsing / quota)
  }
}

export function clearWizardSession(storage: Storage = window.localStorage): void {
  try {
    storage.removeItem(ONBOARDING_SESSION_KEY)
  } catch {
    // ignore
  }
}

/**
 * Resolves the wizard's initial step + state on mount. Falls back to
 * step 1 with EMPTY_STATE when no session is persisted.
 */
export function resolveInitialSession(
  storage: Storage = window.localStorage,
): WizardSession {
  return (
    loadWizardSession(storage) ?? {
      step: 'framework',
      state: EMPTY_STATE,
    }
  )
}
