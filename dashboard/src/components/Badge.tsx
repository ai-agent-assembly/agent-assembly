import type { ReactNode } from 'react'
import './Badge.css'

export type BadgeVariant = 'blue' | 'amber' | 'neutral'

interface BadgeProps {
  variant: BadgeVariant
  children: ReactNode
}

export function Badge({ variant, children }: BadgeProps) {
  return (
    <span className={`badge badge--${variant}`}>
      {children}
    </span>
  )
}
