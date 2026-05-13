import { useEffect } from 'react'
import type { TraceEvent } from '../../features/trace/types'
import './PayloadModal.css'

export interface PayloadModalProps {
  readonly event: TraceEvent | null
  readonly onClose: () => void
}

/**
 * Modal that shows the full pretty-printed JSON payload of a single trace
 * event. Lazy-mounted: returns `null` until an event is selected so the
 * potentially-large `JSON.stringify(payload, null, 2)` only runs while the
 * modal is open.
 *
 * Builds on the scrim+dialog pattern from `features/capability/CellInspectDrawer`.
 * Esc handler, focus trap, and Copy JSON button land in subsequent commits.
 */
export function PayloadModal({ event, onClose }: PayloadModalProps) {
  useEffect(() => {
    if (!event) return
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [event, onClose])

  if (!event) return null

  const formatted = JSON.stringify(event.payload, null, 2)

  return (
    <div
      className="payload-modal-scrim"
      data-testid="payload-modal-scrim"
      onClick={onClose}
    >
      <div
        className="payload-modal"
        role="dialog"
        aria-modal
        aria-label="trace event payload"
        data-testid="payload-modal"
        onClick={e => e.stopPropagation()}
      >
        <header className="payload-modal__head">
          <div>
            <div className="payload-modal__eyebrow">trace event payload</div>
            <h2 className="payload-modal__title">
              <code>{event.type}</code> · <span className="payload-modal__time">{event.timestamp}</span>
            </h2>
            <div className="payload-modal__subtitle">{event.agent} · {event.durationMs}&nbsp;ms</div>
          </div>
          <button
            type="button"
            className="payload-modal__close"
            data-testid="payload-modal-close"
            onClick={onClose}
            aria-label="Close payload modal"
          >
            ✕
          </button>
        </header>

        <pre className="payload-modal__json" data-testid="payload-modal-json">{formatted}</pre>
      </div>
    </div>
  )
}
