import { useEffect, useId, useRef, useState } from 'react'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import type { LiveOperation, OperationOverride } from './types'
import './RowActionMenu.css'

interface RowActionMenuProps {
  op: LiveOperation
  /** Pending action in flight; disables the whole menu while set. */
  override?: OperationOverride
  onPause: () => void
  onResume: () => void
  onTerminate: () => void
}

/**
 * Kebab-popover row action menu mounted in the Live Ops event-stream row
 * (AAASM-1334). Exposes pause / resume / terminate. Items disable
 * themselves based on the operation's current status — pause only on
 * `running`, resume only on `blocked` — and the whole menu disables
 * while a previously-clicked action is still in flight (`override`).
 *
 * Terminate confirmation is layered on top by the consumer (C4).
 */
export function RowActionMenu({
  op,
  override,
  onPause,
  onResume,
  onTerminate,
}: RowActionMenuProps) {
  const [open, setOpen] = useState(false)
  const [confirmingTerminate, setConfirmingTerminate] = useState(false)
  const menuId = useId()
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  const pauseDisabled = op.status !== 'running' || override !== undefined
  const resumeDisabled = op.status !== 'blocked' || override !== undefined
  const terminateDisabled = override !== undefined

  useEffect(() => {
    if (!open) return
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    function handleClick(e: MouseEvent) {
      if (!rootRef.current?.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('keydown', handleKey)
    document.addEventListener('mousedown', handleClick)
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.removeEventListener('mousedown', handleClick)
    }
  }, [open])

  function dispatch(action: () => void) {
    setOpen(false)
    action()
  }

  function handleTerminateClick() {
    setOpen(false)
    setConfirmingTerminate(true)
  }

  function handleConfirmTerminate() {
    setConfirmingTerminate(false)
    onTerminate()
  }

  return (
    <div className="row-actions" ref={rootRef} data-testid="row-action-menu">
      <button
        ref={triggerRef}
        type="button"
        className="row-actions__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Actions for operation ${op.id}`}
        data-testid="row-action-trigger"
        onClick={() => setOpen((v) => !v)}
      >
        ⋮
      </button>
      {open && (
        <ul
          id={menuId}
          className="row-actions__menu"
          role="menu"
          data-testid="row-action-menu-list"
        >
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="row-actions__item"
              disabled={pauseDisabled}
              data-testid="row-action-pause"
              onClick={() => dispatch(onPause)}
            >
              Pause
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="row-actions__item"
              disabled={resumeDisabled}
              data-testid="row-action-resume"
              onClick={() => dispatch(onResume)}
            >
              Resume
            </button>
          </li>
          <li role="none">
            <button
              type="button"
              role="menuitem"
              className="row-actions__item row-actions__item--danger"
              disabled={terminateDisabled}
              data-testid="row-action-terminate"
              onClick={handleTerminateClick}
            >
              Terminate
            </button>
          </li>
        </ul>
      )}
      <ConfirmDialog
        open={confirmingTerminate}
        title="Terminate operation?"
        body={
          <p>
            This will end the operation and free its slot. The agent will see a 499.
            This cannot be undone.
          </p>
        }
        confirmLabel="Terminate"
        confirmVariant="danger"
        onConfirm={handleConfirmTerminate}
        onCancel={() => setConfirmingTerminate(false)}
      />
    </div>
  )
}
