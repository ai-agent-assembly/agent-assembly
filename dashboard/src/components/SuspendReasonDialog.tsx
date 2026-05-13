import { useEffect, useState, type ChangeEvent, type FormEvent, type MouseEvent } from 'react'
import './SuspendReasonDialog.css'

interface SuspendReasonDialogProps {
  /** Title rendered in the dialog head. Defaults to "Suspend agent". */
  title?: string
  /** Body text below the title. Caller customises per single / bulk suspend. */
  body?: string
  /** When `true`, the Confirm button shows a working-state and is disabled. */
  pending?: boolean
  /** Fires with the trimmed, non-empty reason after the user confirms. */
  onConfirm: (reason: string) => void
  /** Fires when the user clicks Cancel, presses Escape, or clicks the scrim. */
  onCancel: () => void
}

/**
 * Modal confirmation for the gateway's `POST /agents/:id/suspend` endpoint.
 * Validates that the textarea is non-empty before firing `onConfirm`.
 */
export function SuspendReasonDialog({
  title = 'Suspend agent',
  body = 'Provide a reason for the audit log. The gateway rejects empty values.',
  pending = false,
  onConfirm,
  onCancel,
}: SuspendReasonDialogProps) {
  const [reason, setReason] = useState('')
  const [touched, setTouched] = useState(false)
  const trimmed = reason.trim()
  const invalid = trimmed === ''

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [onCancel])

  function handleScrimClick(e: MouseEvent<HTMLDivElement>) {
    if (e.target === e.currentTarget) onCancel()
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setTouched(true)
    if (invalid) return
    onConfirm(trimmed)
  }

  return (
    <div
      className="suspend-dialog__scrim"
      onClick={handleScrimClick}
      role="presentation"
      data-testid="suspend-dialog-scrim"
    >
      <form
        className="suspend-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="suspend-dialog-title"
        onSubmit={handleSubmit}
        data-testid="suspend-dialog"
      >
        <h2 id="suspend-dialog-title" className="suspend-dialog__title">
          {title}
        </h2>
        <p className="suspend-dialog__body">{body}</p>
        <label className="suspend-dialog__label" htmlFor="suspend-dialog-input">
          Reason (required)
        </label>
        <textarea
          id="suspend-dialog-input"
          className={`suspend-dialog__input${touched && invalid ? ' suspend-dialog__input--invalid' : ''}`}
          rows={3}
          value={reason}
          onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setReason(e.target.value)}
          onBlur={() => setTouched(true)}
          data-testid="suspend-dialog-input"
          autoFocus
        />
        {touched && invalid && (
          <p className="suspend-dialog__error" data-testid="suspend-dialog-error">
            Reason is required.
          </p>
        )}
        <div className="suspend-dialog__actions">
          <button
            type="button"
            onClick={onCancel}
            className="suspend-dialog__btn"
            data-testid="suspend-dialog-cancel"
          >
            Cancel
          </button>
          <button
            type="submit"
            className="suspend-dialog__btn suspend-dialog__btn--danger"
            disabled={pending || invalid}
            data-testid="suspend-dialog-confirm"
          >
            {pending ? 'Suspending…' : 'Suspend'}
          </button>
        </div>
      </form>
    </div>
  )
}
