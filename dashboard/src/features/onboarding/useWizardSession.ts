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

/**
 * Fields no current build writes, whose presence marks a pre-AAASM-5179 payload.
 *
 * `identity` held a browser-minted DID and a "fingerprint" of unrelated random
 * bytes; `installVerified` recorded a verification no probe ever performed.
 * Neither has a reader any more, so neither could do harm on its own — but a
 * payload carrying them is by definition one this build did not write, and
 * rehydrating a wizard from it would restore progress that was recorded against
 * claims since withdrawn. Rejected outright rather than silently ignored.
 */
const WITHDRAWN_KEYS = ['identity', 'installVerified', 'gatewayReachable'] as const

/**
 * Validates by *shape*, not merely by key presence.
 *
 * Presence alone accepted `{ framework: 42, enrolled: 'yes' }`, which then
 * reached `canAdvance` as a `WizardState` the type system believed. The wizard
 * restarts on anything it cannot vouch for.
 */
function isWizardState(value: unknown): value is WizardState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const v = value as Record<string, unknown>
  if (WITHDRAWN_KEYS.some((key) => key in v)) return false
  return (
    (v.framework === null || typeof v.framework === 'string') &&
    typeof v.gatewayHealthy === 'boolean' &&
    (v.policyPreset === null || typeof v.policyPreset === 'string') &&
    typeof v.enrolled === 'boolean'
  )
}

/**
 * Reads the persisted mid-wizard session from localStorage. Returns null
 * when nothing is persisted, when the payload is malformed, or when the
 * stored step id is no longer in the STEPS table (e.g. after a wizard
 * shape change).
 */
export function loadWizardSession(
  storage: Storage = globalThis.localStorage,
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
  storage: Storage = globalThis.localStorage,
): void {
  try {
    storage.setItem(ONBOARDING_SESSION_KEY, JSON.stringify(session))
  } catch {
    // ignore (private browsing / quota)
  }
}

export function clearWizardSession(storage: Storage = globalThis.localStorage): void {
  try {
    storage.removeItem(ONBOARDING_SESSION_KEY)
  } catch {
    // ignore
  }
}

export interface ResolvedSession extends WizardSession {
  /**
   * A payload was stored and was rejected, so saved progress was dropped.
   *
   * Distinguished from "nothing was stored" so the page can say what happened.
   * Dropping an operator at step 1 with no explanation invites them to assume
   * the wizard lost their work at random; the honest reading is that the saved
   * progress recorded claims this build has withdrawn.
   */
  discarded: boolean
}

/**
 * Resolves the wizard's initial step + state on mount. Falls back to
 * step 1 with EMPTY_STATE when no session is persisted or the persisted one
 * was rejected.
 */
export function resolveInitialSession(
  storage: Storage = globalThis.localStorage,
): ResolvedSession {
  const loaded = loadWizardSession(storage)
  if (loaded) return { ...loaded, discarded: false }

  let stored: string | null = null
  try {
    stored = storage.getItem(ONBOARDING_SESSION_KEY)
  } catch {
    stored = null
  }
  return { step: 'framework', state: EMPTY_STATE, discarded: stored !== null }
}
