import { useState, type ReactNode } from 'react'
import './Tooltip.css'

interface TooltipProps {
  content: string
  children: ReactNode
  /** Force the tooltip open regardless of hover state (for stories and tests). */
  open?: boolean
}

export function Tooltip({ content, children, open = false }: Readonly<TooltipProps>) {
  const [hovered, setHovered] = useState(false)
  // Empty content means "no tooltip" — lets callers conditionally attach a hint
  // (e.g. only when a control is disabled) without wrapping markup twice.
  const visible = (open || hovered) && content.length > 0

  return (
    <span
      className="tooltip-wrapper"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onFocus={() => setHovered(true)}
      onBlur={() => setHovered(false)}
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
