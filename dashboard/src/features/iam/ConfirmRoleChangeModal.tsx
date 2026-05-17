import type { DangerousRoleChange } from './dangerousRoleChange'
import type { Member, Role } from './types'
import './InviteMemberDialog.css'

export interface ConfirmRoleChangeModalProps {
  open: boolean
  member: Member | null
  nextRole: Role | null
  danger: DangerousRoleChange | null
  onCancel: () => void
  onConfirm: () => void
}

export function ConfirmRoleChangeModal({
  open,
  member,
  nextRole,
  danger,
  onCancel,
  onConfirm,
}: ConfirmRoleChangeModalProps) {
  // AAASM-1400 — `danger` may be null for safe changes; the modal still
  // renders, just with a neutral confirmation message instead of the
  // danger-tinted warning. Only `open`, `member`, and `nextRole` gate
  // the render.
  if (!open || !member || !nextRole) return null

  return (
    <div className="iam-dialog__backdrop" role="dialog" aria-modal="true" data-testid="confirm-role-change">
      <div className="iam-dialog">
        <h2 className="iam-dialog__title">Confirm role change</h2>
        <p style={{ fontSize: '0.9rem', margin: '0 0 0.75rem' }}>
          Change <strong>{member.name}</strong>’s role from <strong>{member.role}</strong> to <strong>{nextRole}</strong>?
        </p>
        {danger ? (
          <p
            style={{ fontSize: '0.85rem', color: 'var(--status-danger-hover-text)', margin: 0 }}
            data-testid="confirm-role-warning"
          >
            {danger.message}
          </p>
        ) : (
          <p
            style={{ fontSize: '0.85rem', color: 'var(--text-muted)', margin: 0 }}
            data-testid="confirm-role-neutral"
          >
            This change takes effect immediately for the member.
          </p>
        )}
        <div className="iam-dialog__actions">
          <button type="button" className="iam-dialog__btn" onClick={onCancel} data-testid="confirm-role-cancel">
            Cancel
          </button>
          <button
            type="button"
            className="iam-dialog__btn iam-dialog__btn--primary"
            onClick={onConfirm}
            data-testid="confirm-role-confirm"
          >
            Yes, change role
          </button>
        </div>
      </div>
    </div>
  )
}
