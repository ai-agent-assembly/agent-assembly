import { useEffect, useRef, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import './ConfirmDialog.css'

interface ConfirmDialogProps {
  open: boolean
  title: string
  body?: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  /** Visual treatment of the confirm button. Defaults to primary. */
  confirmVariant?: 'primary' | 'danger'
  onConfirm: () => void
  onCancel: () => void
}

/**
 * Portal-based confirmation modal. Renders above OverlayHost (z-index 200
 * vs 100) so it can sit on top of editor overlays for "discard unsaved
 * changes?" prompts.
 *
 * Esc and backdrop click both call onCancel. Content click does not.
 * The Confirm button receives focus on open for keyboard activation.
 */
export function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmVariant = 'primary',
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const confirmRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    confirmRef.current?.focus()
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onCancel()
      }
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [open, onCancel])

  if (!open || typeof document === 'undefined') return null

  return createPortal(
    <div
      className="confirm-dialog__backdrop"
      data-testid="confirm-dialog-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel()
      }}
    >
      <div className="confirm-dialog" role="alertdialog" aria-modal="true" data-testid="confirm-dialog">
        <h2 className="confirm-dialog__title">{title}</h2>
        {body ? <div className="confirm-dialog__body">{body}</div> : null}
        <div className="confirm-dialog__actions">
          <button
            type="button"
            className="confirm-dialog__btn"
            data-testid="confirm-dialog-cancel"
            onClick={onCancel}
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            type="button"
            className={
              confirmVariant === 'danger'
                ? 'confirm-dialog__btn confirm-dialog__btn--danger'
                : 'confirm-dialog__btn confirm-dialog__btn--primary'
            }
            data-testid="confirm-dialog-confirm"
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}
