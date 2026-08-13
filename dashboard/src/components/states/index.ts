/**
 * Legacy generic state pair, retained for its four existing call sites.
 *
 * Both members now delegate to `components/truthfulness/StatusState` (AAASM-5173)
 * so there is exactly one implementation of an absent-value surface. New work
 * should import `StatusState` from `components/truthfulness` instead — it can
 * express the full vocabulary, where these two can only say "empty" or "failed".
 */
export { EmptyState } from './EmptyState'
export { ErrorState } from './ErrorState'
