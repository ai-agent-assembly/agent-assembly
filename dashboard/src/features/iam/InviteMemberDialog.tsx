import { useId, useState } from 'react'
import { ROLES, type Role, type InviteMemberInput } from './types'
import { isValidEmail } from './validation'
import './InviteMemberDialog.css'

export interface InviteMemberDialogProps {
  open: boolean
  onClose: () => void
  onSubmit: (input: InviteMemberInput) => void | Promise<void>
  isSubmitting?: boolean
}

export function InviteMemberDialog({ open, onClose, onSubmit, isSubmitting }: InviteMemberDialogProps) {
  if (!open) return null
  return (
    <InviteMemberDialogBody
      onClose={onClose}
      onSubmit={onSubmit}
      isSubmitting={isSubmitting}
    />
  )
}

function InviteMemberDialogBody({ onClose, onSubmit, isSubmitting }: Omit<InviteMemberDialogProps, 'open'>) {
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<Role>('Member')
  const [touched, setTouched] = useState(false)
  const emailId = useId()
  const roleId = useId()

  const trimmed = email.trim()
  const emailValid = isValidEmail(trimmed)
  const showError = touched && !emailValid

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setTouched(true)
    if (!emailValid) return
    void onSubmit({ email: trimmed, role })
  }

  return (
    <div className="iam-dialog__backdrop" role="dialog" aria-modal="true" aria-labelledby={`${emailId}-title`} data-testid="invite-member-dialog">
      <form className="iam-dialog" onSubmit={handleSubmit}>
        <h2 id={`${emailId}-title`} className="iam-dialog__title">Invite member</h2>

        <label htmlFor={emailId} className="iam-dialog__label">Email</label>
        <input
          id={emailId}
          autoFocus
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onBlur={() => setTouched(true)}
          aria-invalid={showError}
          aria-describedby={showError ? `${emailId}-error` : undefined}
          className="iam-dialog__input"
          data-testid="invite-email-input"
          placeholder="name@company.com"
          required
        />
        {showError && (
          <div id={`${emailId}-error`} className="iam-dialog__error" data-testid="invite-email-error">
            Enter a valid email address.
          </div>
        )}

        <label htmlFor={roleId} className="iam-dialog__label">Role</label>
        <select
          id={roleId}
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          className="iam-dialog__input"
          data-testid="invite-role-select"
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>

        <div className="iam-dialog__actions">
          <button type="button" className="iam-dialog__btn" onClick={onClose} data-testid="invite-cancel">
            Cancel
          </button>
          <button
            type="submit"
            className="iam-dialog__btn iam-dialog__btn--primary"
            disabled={isSubmitting}
            data-testid="invite-submit"
          >
            {isSubmitting ? 'Sending…' : 'Send invitation'}
          </button>
        </div>
      </form>
    </div>
  )
}
