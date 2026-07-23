import { useEffect, useMemo, useRef, type KeyboardEvent } from 'react'
import type { TraceEvent } from '../../features/trace/types'
import { deriveVerdict } from '../../features/trace/decision'
import { VerdictChip } from './VerdictChip'
import { DecisionExplainer } from './DecisionExplainer'
import './PayloadModal.css'

export interface PayloadModalProps {
  readonly event: TraceEvent | null
  readonly onClose: () => void
}

/**
 * Decision-explainer modal for a single trace event (AAASM-5027).
 *
 * Replaces the former raw-JSON + 🔒 payload dump: the body now renders the
 * hi-fi L0–L3 explainer (layer steps + outcome band + redaction-block preview)
 * via `DecisionExplainer`, and the header carries the verdict chip. The
 * scrim / Esc / backdrop-click / focus-trap shell is unchanged so the page's
 * open-close wiring keeps working. Redacted values are never rendered — the
 * preview shows `█` blocks — so there is no raw-value copy affordance.
 */
const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function PayloadModal({ event, onClose }: PayloadModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const closeBtnRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!event) return
    const handleKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [event, onClose])

  // Focus the Close button on open so keyboard users land inside the modal.
  useEffect(() => {
    if (!event) return
    closeBtnRef.current?.focus()
  }, [event])

  const handleFocusTrap = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab' || !dialogRef.current) return
    const focusables = dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
    if (focusables.length === 0) return
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault()
      last.focus()
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault()
      first.focus()
    }
  }

  const verdict = useMemo(() => (event ? deriveVerdict(event) : null), [event])

  if (!event || !verdict) return null

  return (
    <div
      className="payload-modal-scrim"
      data-testid="payload-modal-scrim"
      onClick={onClose}
      onKeyDown={e => {
        if (e.target !== e.currentTarget) return
        if (e.key !== 'Enter' && e.key !== ' ') return
        e.preventDefault()
        onClose()
      }}
      role="button"
      tabIndex={-1}
      aria-label="Close decision explainer"
    >
      <div
        ref={dialogRef}
        className="payload-modal"
        role="dialog"
        aria-modal
        aria-label="trace decision explainer"
        data-testid="payload-modal"
        onClick={e => e.stopPropagation()}
        onKeyDown={handleFocusTrap}
      >
        <header className="payload-modal__head">
          <div>
            <div className="payload-modal__eyebrow">trace decision explainer</div>
            <h2 className="payload-modal__title">
              <VerdictChip verdict={verdict} />{' '}
              <code>{event.type}</code> · <span className="payload-modal__time">{event.timestamp}</span>
            </h2>
            <div className="payload-modal__subtitle">{event.agent} · {event.durationMs}&nbsp;ms</div>
          </div>
          <div className="payload-modal__actions">
            <button
              ref={closeBtnRef}
              type="button"
              className="payload-modal__close"
              data-testid="payload-modal-close"
              onClick={onClose}
              aria-label="Close decision explainer"
            >
              ✕
            </button>
          </div>
        </header>

        <div className="payload-modal__body" data-testid="payload-modal-body">
          <DecisionExplainer event={event} />
        </div>
      </div>
    </div>
  )
}
