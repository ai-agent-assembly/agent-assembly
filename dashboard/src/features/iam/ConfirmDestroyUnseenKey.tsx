export interface ConfirmDestroyUnseenKeyProps {
  open: boolean
  onKeepShowing: () => void
  onDiscardSecret: () => void
}

/**
 * Last-chance prompt before a generated secret is wiped from memory
 * without the operator copying it. Shown when the operator attempts
 * to close the RevealOnceModal before pressing Copy.
 */
export function ConfirmDestroyUnseenKey({ open, onKeepShowing, onDiscardSecret }: ConfirmDestroyUnseenKeyProps) {
  if (!open) return null
  return (
    <div className="iam-dialog__backdrop" role="dialog" aria-modal="true" data-testid="confirm-destroy-unseen-key">
      <div className="iam-dialog" style={{ zIndex: 2000 }}>
        <h2 className="iam-dialog__title">Discard this key?</h2>
        <p style={{ fontSize: '0.9rem', margin: 0 }}>
          You will not be able to view this key again. Closing now means you must generate a new key to use it.
        </p>
        <div className="iam-dialog__actions">
          <button
            type="button"
            className="iam-dialog__btn iam-dialog__btn--primary"
            onClick={onKeepShowing}
            data-testid="destroy-unseen-keep"
          >
            Keep showing it
          </button>
          <button
            type="button"
            className="iam-dialog__btn iam-dialog__btn--danger"
            onClick={onDiscardSecret}
            data-testid="destroy-unseen-discard"
          >
            Discard anyway
          </button>
        </div>
      </div>
    </div>
  )
}
