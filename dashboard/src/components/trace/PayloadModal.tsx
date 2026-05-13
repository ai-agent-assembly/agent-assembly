import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import type { TraceEvent } from '../../features/trace/types'
import { Tooltip } from '../Tooltip'
import './PayloadModal.css'

const REDACTED_LINE_RE = /^(\s*)"([^"]+)":\s*(.*?)(,?)\s*$/

function renderJsonLines(formatted: string, redactedSet: ReadonlySet<string>): ReactNode[] {
  return formatted.split('\n').map((line, i) => {
    const match = REDACTED_LINE_RE.exec(line)
    if (match && redactedSet.has(match[2])) {
      const [, indent, key, , trailing] = match
      const sentinel = `"<redacted: ${key}>"`
      return (
        <span key={i} data-testid="redacted-field" className="payload-modal__redacted">
          {indent}&quot;{key}&quot;:{' '}
          <Tooltip content="Redacted by policy">
            <span className="payload-modal__lock" aria-label={`${key} is redacted by policy`}>🔒</span>
          </Tooltip>
          {' '}{sentinel}{trailing}
          {'\n'}
        </span>
      )
    }
    return (
      <span key={i}>
        {line}
        {'\n'}
      </span>
    )
  })
}

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
const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function PayloadModal({ event, onClose }: PayloadModalProps) {
  const [copied, setCopied] = useState(false)
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

  const redactedSet = useMemo(
    () => new Set(event?.redactedFields ?? []),
    [event?.redactedFields],
  )

  if (!event) return null

  const formatted = JSON.stringify(event.payload, null, 2)
  const jsonNodes = renderJsonLines(formatted, redactedSet)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(formatted)
    setCopied(true)
  }

  return (
    <div
      className="payload-modal-scrim"
      data-testid="payload-modal-scrim"
      onClick={onClose}
    >
      <div
        ref={dialogRef}
        className="payload-modal"
        role="dialog"
        aria-modal
        aria-label="trace event payload"
        data-testid="payload-modal"
        onClick={e => e.stopPropagation()}
        onKeyDown={handleFocusTrap}
      >
        <header className="payload-modal__head">
          <div>
            <div className="payload-modal__eyebrow">trace event payload</div>
            <h2 className="payload-modal__title">
              <code>{event.type}</code> · <span className="payload-modal__time">{event.timestamp}</span>
            </h2>
            <div className="payload-modal__subtitle">{event.agent} · {event.durationMs}&nbsp;ms</div>
          </div>
          <div className="payload-modal__actions">
            <button
              type="button"
              className="payload-modal__copy"
              data-testid="payload-modal-copy"
              onClick={() => void handleCopy()}
            >
              {copied ? 'Copied' : 'Copy JSON'}
            </button>
            <button
              ref={closeBtnRef}
              type="button"
              className="payload-modal__close"
              data-testid="payload-modal-close"
              onClick={onClose}
              aria-label="Close payload modal"
            >
              ✕
            </button>
          </div>
        </header>

        <pre className="payload-modal__json" data-testid="payload-modal-json">{jsonNodes}</pre>
      </div>
    </div>
  )
}
