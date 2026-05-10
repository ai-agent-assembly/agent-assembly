import { useState, type ReactNode } from 'react'
import './Tooltip.css'

interface TooltipProps {
  content: string
  children: ReactNode
  /** Force the tooltip open regardless of hover state (for stories and tests). */
  open?: boolean
}

export function Tooltip({ content, children, open = false }: TooltipProps) {
  const [hovered, setHovered] = useState(false)
  const visible = open || hovered

  return (
    <span
      className="tooltip-wrapper"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {children}
      {visible && (
        <span role="tooltip" className="tooltip-popup">
          {content}
        </span>
      )}
    </span>
  )
}
