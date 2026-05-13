import { Suspense, lazy, useEffect, useRef, type KeyboardEvent } from 'react'
import { useTraceDrawer } from './useTraceDrawer'
import './TraceDrawer.css'

const TraceViewPage = lazy(() =>
  import('../../pages/TraceViewPage').then(m => ({ default: m.TraceViewPage })),
)

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Shell-level trace overlay. A single instance is mounted by `<AppShell>`;
 * any routed page calls `useTraceDrawer().open(agentId, sessionId)` to
 * surface it.
 *
 * - Animates in from the right.
 * - Esc + backdrop click close.
 * - Tab cycles focus between focusables inside the drawer.
 * - TraceViewPage is lazy-loaded so the initial bundle stays slim.
 */
export function TraceDrawer() {
  const { state, close } = useTraceDrawer()
  const drawerRef = useRef<HTMLDivElement>(null)
  const closeBtnRef = useRef<HTMLButtonElement>(null)
  const open = state.agentId !== null && state.sessionId !== null

  useEffect(() => {
    if (!open) return
    const handleKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open, close])

  // Focus the close button when the drawer opens for a new agent/session.
  useEffect(() => {
    if (!open) return
    closeBtnRef.current?.focus()
  }, [open, state.agentId, state.sessionId])

  if (!open) return null

  const handleFocusTrap = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab' || !drawerRef.current) return
    const focusables = drawerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
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

  return (
    <div
      className="trace-drawer-scrim"
      data-testid="trace-drawer-scrim"
      onClick={close}
    >
      <div
        ref={drawerRef}
        className="trace-drawer"
        role="dialog"
        aria-modal
        aria-label="Agent trace"
        data-testid="trace-drawer"
        onClick={e => e.stopPropagation()}
        onKeyDown={handleFocusTrap}
      >
        <header className="trace-drawer__head">
          <div className="trace-drawer__eyebrow">trace</div>
          <button
            ref={closeBtnRef}
            type="button"
            className="trace-drawer__close"
            data-testid="trace-drawer-close"
            aria-label="Close trace drawer"
            onClick={close}
          >
            ✕
          </button>
        </header>
        <div className="trace-drawer__body" data-testid="trace-drawer-body">
          <Suspense fallback={<div className="trace-drawer__loading">Loading trace…</div>}>
            <TraceViewPage agentId={state.agentId!} sessionId={state.sessionId!} />
          </Suspense>
        </div>
      </div>
    </div>
  )
}
