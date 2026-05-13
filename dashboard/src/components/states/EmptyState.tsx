import type { ReactNode } from 'react'
import './states.css'

interface EmptyStateProps {
  title: string
  description?: ReactNode
  action?: ReactNode
  icon?: ReactNode
}

export function EmptyState({ title, description, action, icon }: EmptyStateProps) {
  return (
    <div className="state state--empty" role="status" data-testid="empty-state">
      {icon ? <div className="state__icon">{icon}</div> : null}
      <h2 className="state__title">{title}</h2>
      {description ? <div className="state__description">{description}</div> : null}
      {action ? <div className="state__action">{action}</div> : null}
    </div>
  )
}
