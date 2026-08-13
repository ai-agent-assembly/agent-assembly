import { useEffect, useId, useRef, useState } from 'react'
import { ConfirmDialog } from '../../components/ConfirmDialog'
import { usePermissions, WRITE_REQUIRED_HINT } from '../../auth/usePermissions'
import type { LiveOperation, OperationOverride } from './types'
import './RowActionMenu.css'

interface RowActionMenuProps {
  op: LiveOperation
  /** Pending action in flight; disables the whole menu while set. */
  override?: OperationOverride
  onPause: () => void
  onResume: () => void
  onTerminate: () => void
  /**
   * Halt the agent owning this op (fleet-scoped kill for one agent). Optional:
   * the item only renders when a handler is supplied, so surfaces that only
   * expose per-op lifecycle actions stay unchanged.
   */
  onHaltAgent?: () => void
}

/**
 * Kebab-popover row action menu mounted in the Live Ops event-stream row
 * (AAASM-1334). Exposes pause / resume / terminate. Items disable
 * themselves based on the operation's current status — pause only on
 * `running`, resume only on `blocked` — and the whole menu disables
 * while a previously-clicked action is still in flight (`override`).
 *
 * Terminate confirmation is layered on top by the consumer (C4).
 *
 * AAASM-5148: every item here POSTs to `/api/v1/ops/...`, so the menu re-derives
 * `canWrite` itself rather than taking it as a prop — the gate then holds for
 * any surface that mounts a row, and cannot be forgotten by a new caller.
 */
export function RowActionMenu({
  op,
  override,
  onPause,
  onResume,
  onTerminate,
  onHaltAgent,
}: Readonly<RowActionMenuProps>) {
  const [open, setOpen] = useState(false)
  const [confirmingTerminate, setConfirmingTerminate] = useState(false)
  const [confirmingHalt, setConfirmingHalt] = useState(false)
  const menuId = useId()
  const rootRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const { canWrite } = usePermissions()

  const pauseDisabled = !canWrite || op.status !== 'running' || override !== undefined
  const resumeDisabled = !canWrite || op.status !== 'blocked' || override !== undefined
  const terminateDisabled = !canWrite || override !== undefined
  const writeHint = canWrite ? undefined : WRITE_REQUIRED_HINT

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

  function handleHaltAgentClick() {
    setOpen(false)
    setConfirmingHalt(true)
  }

  function handleConfirmHalt() {
    setConfirmingHalt(false)
    onHaltAgent?.()
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
              title={writeHint}
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
              title={writeHint}
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
              title={writeHint}
              data-testid="row-action-terminate"
              onClick={handleTerminateClick}
            >
              Terminate
            </button>
          </li>
          {onHaltAgent && (
            <li role="none">
              <button
                type="button"
                role="menuitem"
                className="row-actions__item row-actions__item--danger"
                disabled={!canWrite || override !== undefined}
                title={writeHint}
                data-testid="row-action-halt-agent"
                onClick={handleHaltAgentClick}
              >
                Halt agent
              </button>
            </li>
          )}
        </ul>
      )}
      {/* AAASM-5148: the dialog's confirm button is the true last control, and
          it lives in a shared component this lane does not own. Gating the
          dialog's own visibility on `canWrite` closes that gap without forking
          ConfirmDialog — and it also handles the reachable case the menu items
          alone do not: an operator who opened the dialog while holding `write`
          and lost the scope before confirming. */}
      <ConfirmDialog
        open={confirmingTerminate && canWrite}
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
      <ConfirmDialog
        open={confirmingHalt && canWrite}
        title="Halt this agent?"
        body={
          <p>
            This stops every in-flight operation for{' '}
            <b>{op.agent}</b>, not just this one. The agent will need to be
            resumed before it can act again.
          </p>
        }
        confirmLabel="Halt agent"
        confirmVariant="danger"
        onConfirm={handleConfirmHalt}
        onCancel={() => setConfirmingHalt(false)}
      />
    </div>
  )
}
