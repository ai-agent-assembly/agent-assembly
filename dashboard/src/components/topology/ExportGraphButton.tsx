import { useEffect, useRef, useState } from 'react'
import './ExportGraphButton.css'

export interface ExportGraphButtonProps {
  readonly onExportSvg: () => void
  readonly onExportJson: () => void
}

/**
 * "Export graph" split control (AAASM-5071). Mirrors the hi-fi reference's
 * single export affordance, but offers the two client-side formats the task
 * calls for — SVG (a rendered snapshot) and JSON (the raw view model). The menu
 * closes on selection or an outside click.
 */
export function ExportGraphButton({ onExportSvg, onExportJson }: ExportGraphButtonProps) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDown)
    return () => document.removeEventListener('mousedown', onDown)
  }, [open])

  const choose = (fn: () => void) => {
    setOpen(false)
    fn()
  }

  return (
    <div className="topo-export" ref={rootRef}>
      <button
        type="button"
        className="topo-export__btn"
        data-testid="topology-export-button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        ⏏ export graph
      </button>
      {open && (
        <div className="topo-export__menu" role="menu" data-testid="topology-export-menu">
          <button type="button" role="menuitem" className="topo-export__item" data-testid="topology-export-svg" onClick={() => choose(onExportSvg)}>
            Export SVG
          </button>
          <button type="button" role="menuitem" className="topo-export__item" data-testid="topology-export-json" onClick={() => choose(onExportJson)}>
            Export JSON
          </button>
        </div>
      )}
    </div>
  )
}
