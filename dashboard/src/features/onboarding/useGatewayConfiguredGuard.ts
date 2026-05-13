export const ONBOARDING_COMPLETED_KEY = 'aa.onboarding.completed'

/**
 * Reads the localStorage flag the wizard sets when it finishes (or when the
 * user clicks "skip onboarding"). Synchronous so the page can decide whether
 * to render the wizard or redirect *before* the first paint — avoiding a
 * flash of the modal for already-set-up users.
 */
export function isGatewayConfigured(storage: Storage = window.localStorage): boolean {
  try {
    return storage.getItem(ONBOARDING_COMPLETED_KEY) === 'true'
  } catch {
    return false
  }
}

export function markGatewayConfigured(storage: Storage = window.localStorage): void {
  try {
    storage.setItem(ONBOARDING_COMPLETED_KEY, 'true')
  } catch {
    // ignore (private browsing / quota)
  }
}

export function clearGatewayConfigured(storage: Storage = window.localStorage): void {
  try {
    storage.removeItem(ONBOARDING_COMPLETED_KEY)
  } catch {
    // ignore
  }
}

/**
 * Hook wrapper around isGatewayConfigured(). Reads once on mount; the
 * wizard never needs to react to runtime changes (the user can't toggle
 * gateway-configured state from another tab while the wizard is open).
 */
export function useGatewayConfiguredGuard(): boolean {
  return isGatewayConfigured()
}
