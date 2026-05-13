import type { ReactNode } from 'react'
import './LockedFeatureCard.css'

export interface LockedFeatureCardProps {
  title: string
  body: string
  /** Rendered to the right of the body — typically a CTA button or link. */
  cta?: ReactNode
  testId?: string
}

export function LockedFeatureCard({ title, body, cta, testId = 'locked-feature-card' }: LockedFeatureCardProps) {
  return (
    <div className="iam-locked-card" data-testid={testId} role="region" aria-label={title}>
      <div className="iam-locked-card__lock-badge" aria-hidden="true">🔒</div>
      <div className="iam-locked-card__copy">
        <h3 className="iam-locked-card__title">{title}</h3>
        <p className="iam-locked-card__body">{body}</p>
      </div>
      {cta && <div className="iam-locked-card__cta">{cta}</div>}
    </div>
  )
}
