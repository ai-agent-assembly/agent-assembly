import type { ReactNode } from 'react'
import { StatusState } from '../truthfulness'

interface ErrorStateProps {
  title: string
  description?: ReactNode
  onRetry?: () => void
  retryLabel?: string
}

/**
 * A failed request — the `unavailable` state of the shared vocabulary.
 *
 * Converged onto `StatusState` under AAASM-5173. Props, the `error-state` test
 * id, and `role="alert"` are unchanged for the existing call sites; the state
 * badge and the screen-reader announcement now come from the shared vocabulary,
 * so a failure can no longer be announced as anything milder than a fault.
 *
 * @deprecated for new surfaces — use `StatusState` directly. A hook that failed
 * and a hook that returned nothing are different facts, and only `StatusState`
 * can distinguish them.
 */
export function ErrorState({
  title,
  description,
  onRetry,
  retryLabel = 'Retry',
}: Readonly<ErrorStateProps>) {
  return (
    <StatusState
      state="unavailable"
      title={title}
      description={description}
      testId="error-state"
      action={
        onRetry ? (
          <button type="button" className="truth-state__retry" onClick={onRetry}>
            {retryLabel}
          </button>
        ) : undefined
      }
    />
  )
}
