import { useEffect, useMemo, useRef, useState, type ChangeEvent, type SyntheticEvent } from 'react'
import type {
  CascadeConfirmation,
  EnforcementModeCascadePreviewResponse,
} from '../../features/agents/mutations'
import '../SuspendReasonDialog.css'
import './ShadowModeDialog.css'

/** How far ahead of now the shadow window may be set, mirroring the server's SHADOW_MAX_HOURS. */
const SHADOW_MAX_HOURS = 72

/** The collected weaken payload the caller submits to `useSetEnforcementMode`. */
export interface ShadowSubmit {
  reason: string
  /** ISO-8601 UTC deadline. */
  expiresAt: string
  /** Present only when the operator confirmed a cascade, echoed from the preview. */
  cascade?: CascadeConfirmation
}

interface ShadowModeDialogProps {
  /** Agent display name, shown in the title. */
  readonly agentName: string
  /** Whether the apply mutation is in flight (disables the confirm button). */
  readonly pending: boolean
  /**
   * Preview trigger. The dialog calls this when the operator asks to cascade;
   * the caller runs `usePreviewEnforcementCascade` and resolves with the
   * affected set (or rejects, so the dialog can surface the server message).
   */
  readonly onPreview: () => Promise<EnforcementModeCascadePreviewResponse>
  /** Whether a preview request is currently in flight. */
  readonly previewPending: boolean
  /** Server-authoritative error text to surface (422/403/409 from apply or preview). */
  readonly serverError?: string | null
  /** Fires with the collected reason + expiry (+ cascade echo-back on confirm). */
  readonly onConfirm: (submit: ShadowSubmit) => void
  /** Fires on Cancel, Escape, or scrim click. */
  readonly onCancel: () => void
}

/**
 * Convert a `datetime-local` value (local wall-clock, no zone) to an ISO-8601
 * UTC string the gateway accepts, or `null` when the field is empty.
 */
function toIso(local: string): string | null {
  if (local === '') return null
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? null : d.toISOString()
}

/** Client-side hint only — the server is authoritative. `null` = no complaint. */
function expiryHint(local: string): string | null {
  const iso = toIso(local)
  if (iso === null) return 'An expiry is required.'
  const ms = new Date(iso).getTime() - Date.now()
  if (ms <= 0) return 'The expiry must be in the future.'
  if (ms > SHADOW_MAX_HOURS * 3_600_000) return `The expiry must be within ${SHADOW_MAX_HOURS}h from now.`
  return null
}

/**
 * The weaken (→ shadow) form: collects the required reason + expiry, offers a
 * single-agent vs cascade choice, and — when cascade is chosen — runs the
 * preview and shows the explicit affected-agent list for an explicit confirm.
 *
 * Modeled on {@link SuspendReasonDialog}; reuses its CSS for the scrim/inputs.
 * All validation here is an advisory hint — the gateway re-checks reason,
 * expiry window, Admin scope, tenant, and the cascade echo-back, and its
 * rejections (403/422/409) are surfaced via `serverError`.
 */
export function ShadowModeDialog({
  agentName,
  pending,
  onPreview,
  previewPending,
  serverError,
  onConfirm,
  onCancel,
}: Readonly<ShadowModeDialogProps>) {
  const [reason, setReason] = useState('')
  const [expiresLocal, setExpiresLocal] = useState('')
  const [cascade, setCascade] = useState(false)
  const [touched, setTouched] = useState(false)
  const [preview, setPreview] = useState<EnforcementModeCascadePreviewResponse | null>(null)
  const dialogRef = useRef<HTMLDialogElement>(null)

  const trimmed = reason.trim()
  const reasonInvalid = trimmed === ''
  const expiryComplaint = expiryHint(expiresLocal)
  const formInvalid = reasonInvalid || expiryComplaint !== null

  // A change to the form or the cascade choice invalidates a stale preview: the
  // operator must re-preview before the confirm can echo it back. Done in the
  // change handlers (not an effect) so it never triggers a cascading render.
  const invalidatePreview = () => setPreview(null)

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [onCancel])

  const iso = useMemo(() => toIso(expiresLocal), [expiresLocal])

  // Backdrop dismiss: a click landing outside the box's bounds means the scrim
  // was hit. Attached imperatively rather than via a React `onClick` prop
  // because a <dialog> is a non-interactive element — a JSX listener on it trips
  // jsx-a11y (S6847); the keyboard dismiss path is the Escape handler above.
  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return
    const onBackdrop = (e: globalThis.MouseEvent) => {
      if (e.target === dialog) onCancel()
    }
    dialog.addEventListener('click', onBackdrop)
    return () => dialog.removeEventListener('click', onBackdrop)
  }, [onCancel])

  async function runPreview() {
    setTouched(true)
    if (formInvalid) return
    const result = await onPreview()
    setPreview(result)
  }

  function handleSubmit(e: SyntheticEvent) {
    e.preventDefault()
    setTouched(true)
    if (formInvalid || iso === null) return
    if (cascade) {
      // Cascade requires an explicit confirm off a live preview; the button
      // becomes "confirm" only once a preview is present, so this branch is
      // reached only with `preview` set.
      if (!preview) return
      onConfirm({
        reason: trimmed,
        expiresAt: iso,
        cascade: { expected_ids: preview.affected_ids, expected_count: preview.count },
      })
      return
    }
    onConfirm({ reason: trimmed, expiresAt: iso })
  }

  const needsPreview = cascade && !preview
  let confirmLabel: string
  if (pending) {
    confirmLabel = 'Applying…'
  } else if (cascade) {
    confirmLabel = `Shadow ${preview?.count ?? ''} agents`.trim()
  } else {
    confirmLabel = 'Switch to shadow'
  }

  return (
    <dialog
      ref={dialogRef}
      open
      className="suspend-dialog__scrim"
      aria-modal="true"
      aria-label="Close dialog"
      data-testid="shadow-dialog-scrim"
    >
      <form
        className="suspend-dialog"
        aria-labelledby="shadow-dialog-title"
        onSubmit={handleSubmit}
        data-testid="shadow-dialog"
      >
        <h2 id="shadow-dialog-title" className="suspend-dialog__title">
          Switch {agentName} to shadow mode
        </h2>
        <p className="suspend-dialog__body">
          Shadow mode turns denials and credential redaction off for the agent — it fails open.
          It requires a reason for the audit log and a deadline (within {SHADOW_MAX_HOURS}h). The
          gateway re-checks Admin scope, the expiry window, and tenant ownership.
        </p>

        <label className="suspend-dialog__label" htmlFor="shadow-dialog-reason">
          Reason (required)
        </label>
        <textarea
          id="shadow-dialog-reason"
          className={`suspend-dialog__input${touched && reasonInvalid ? ' suspend-dialog__input--invalid' : ''}`}
          rows={2}
          value={reason}
          onChange={(e: ChangeEvent<HTMLTextAreaElement>) => { setReason(e.target.value); invalidatePreview() }}
          onBlur={() => setTouched(true)}
          data-testid="shadow-dialog-reason"
          autoFocus
        />
        {touched && reasonInvalid && (
          <p className="suspend-dialog__error" data-testid="shadow-dialog-reason-error">
            Reason is required.
          </p>
        )}

        <label className="suspend-dialog__label" htmlFor="shadow-dialog-expiry">
          Expires at (required, ≤{SHADOW_MAX_HOURS}h)
        </label>
        <input
          id="shadow-dialog-expiry"
          type="datetime-local"
          className={`suspend-dialog__input${touched && expiryComplaint !== null ? ' suspend-dialog__input--invalid' : ''}`}
          value={expiresLocal}
          onChange={(e: ChangeEvent<HTMLInputElement>) => { setExpiresLocal(e.target.value); invalidatePreview() }}
          onBlur={() => setTouched(true)}
          data-testid="shadow-dialog-expiry"
        />
        {touched && expiryComplaint !== null && (
          <p className="suspend-dialog__error" data-testid="shadow-dialog-expiry-error">
            {expiryComplaint}
          </p>
        )}

        <label className="shadow-dialog__cascade-choice">
          <input
            type="checkbox"
            checked={cascade}
            onChange={(e: ChangeEvent<HTMLInputElement>) => { setCascade(e.target.checked); invalidatePreview() }}
            data-testid="shadow-dialog-cascade-toggle"
          />
          <span>Cascade to the whole subtree (not just this agent)</span>
        </label>

        {cascade && preview && (
          <div className="shadow-dialog__preview" data-testid="shadow-dialog-preview">
            <p className="shadow-dialog__preview-head" data-testid="shadow-dialog-preview-count">
              This will shadow these {preview.count} agent{preview.count === 1 ? '' : 's'}:
            </p>
            <ul className="shadow-dialog__preview-list">
              {preview.affected_ids.map((id) => (
                <li key={id} data-testid="shadow-dialog-preview-id">
                  <code>{id}</code>
                </li>
              ))}
            </ul>
          </div>
        )}

        {serverError && (
          <p className="suspend-dialog__error" data-testid="shadow-dialog-server-error" role="alert">
            {serverError}
          </p>
        )}

        <div className="suspend-dialog__actions">
          <button
            type="button"
            onClick={onCancel}
            className="suspend-dialog__btn"
            data-testid="shadow-dialog-cancel"
          >
            Cancel
          </button>
          {needsPreview ? (
            <button
              type="button"
              className="suspend-dialog__btn suspend-dialog__btn--danger"
              disabled={previewPending || formInvalid}
              onClick={() => { void runPreview() }}
              data-testid="shadow-dialog-preview-btn"
            >
              {previewPending ? 'Previewing…' : 'Preview cascade'}
            </button>
          ) : (
            <button
              type="submit"
              className="suspend-dialog__btn suspend-dialog__btn--danger"
              disabled={pending || formInvalid}
              data-testid="shadow-dialog-confirm"
            >
              {confirmLabel}
            </button>
          )}
        </div>
      </form>
    </dialog>
  )
}
