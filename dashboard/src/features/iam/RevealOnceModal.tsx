import { useEffect, useRef } from 'react'
import { useToast } from '../../components/Toast'
import type { GeneratedApiKey } from './types'

/** Autoclose delay after a successful copy, in milliseconds. */
export const REVEAL_AUTOCLOSE_MS = 2000

export interface RevealOnceModalProps {
  /** The just-generated key. The component does not retain or log the secret. */
  generated: GeneratedApiKey
  /** Set by the parent when the operator has copied the secret. */
  copied: boolean
  /** Called by this component when the operator presses copy. */
  onCopied: () => void
  /** Called when the modal should close (autoclose, explicit close, etc.). */
  onClose: () => void
  /** Called when the operator attempts to close before copying. */
  onAttemptCloseBeforeCopy: () => void
}

export function RevealOnceModal({
  generated,
  copied,
  onCopied,
  onClose,
  onAttemptCloseBeforeCopy,
}: RevealOnceModalProps) {
  const { toast } = useToast()
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (!copied) return
    closeTimer.current = setTimeout(onClose, REVEAL_AUTOCLOSE_MS)
    return () => {
      if (closeTimer.current) clearTimeout(closeTimer.current)
    }
  }, [copied, onClose])

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(generated.secret)
      onCopied()
      toast('Copied to clipboard. You will not see this key again.', 'success')
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Clipboard write failed', 'error')
    }
  }

  function handleBackdropAttempt() {
    if (copied) onClose()
    else onAttemptCloseBeforeCopy()
  }

  return (
    <div
      className="iam-dialog__backdrop"
      role="dialog"
      aria-modal="true"
      data-testid="reveal-once-modal"
      onClick={handleBackdropAttempt}
    >
      <div className="iam-dialog" onClick={(e) => e.stopPropagation()}>
        <h2 className="iam-dialog__title">Your new API key</h2>
        <p style={{ fontSize: '0.85rem', margin: '0 0 0.75rem' }}>
          Copy this secret now — it will not be shown again.
        </p>
        <input
          readOnly
          className="iam-dialog__input"
          value={generated.secret}
          data-testid="reveal-once-secret"
          style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, monospace' }}
          onFocus={(e) => e.currentTarget.select()}
        />
        <div className="iam-dialog__actions">
          {copied && (
            <span data-testid="reveal-once-copied" style={{ marginRight: 'auto', color: 'var(--status-success-solid)', fontSize: '0.85rem' }}>
              Copied — closing…
            </span>
          )}
          <button
            type="button"
            className="iam-dialog__btn"
            onClick={handleBackdropAttempt}
            data-testid="reveal-once-close"
          >
            {copied ? 'Close' : 'Close without copying'}
          </button>
          <button
            type="button"
            className="iam-dialog__btn iam-dialog__btn--primary"
            onClick={handleCopy}
            disabled={copied}
            data-testid="copy-secret-button"
          >
            {copied ? 'Copied' : 'Copy to clipboard'}
          </button>
        </div>
      </div>
    </div>
  )
}
