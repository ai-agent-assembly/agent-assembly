import type { ReactNode } from 'react'
import './states.css'

interface ErrorStateProps {
  title: string
  description?: ReactNode
  onRetry?: () => void
  retryLabel?: string
}

export function ErrorState({
  title,
  description,
  onRetry,
  retryLabel = 'Retry',
}: ErrorStateProps) {
  return (
    <div className="state state--error" role="alert" data-testid="error-state">
      <h2 className="state__title">{title}</h2>
      {description ? <div className="state__description">{description}</div> : null}
      {onRetry ? (
        <button type="button" className="state__retry" onClick={onRetry}>
          {retryLabel}
        </button>
      ) : null}
    </div>
  )
}
