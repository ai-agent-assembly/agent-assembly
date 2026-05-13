import { useMembersQuery } from './api'
import type { Member, Role } from './types'
import './MemberList.css'

const ROLE_BADGE_TONE: Record<Role, string> = {
  Owner: 'iam-role-badge--owner',
  Admin: 'iam-role-badge--admin',
  Member: 'iam-role-badge--member',
  Viewer: 'iam-role-badge--viewer',
}

function Avatar({ name }: { name: string }) {
  const initial = name.trim().charAt(0).toUpperCase() || '?'
  return <div className="iam-avatar" aria-hidden="true">{initial}</div>
}

function RoleBadge({ role }: { role: Role }) {
  return <span className={`iam-role-badge ${ROLE_BADGE_TONE[role]}`}>{role}</span>
}

function StatusCell({ status }: { status: Member['status'] }) {
  return <span className={`iam-status iam-status--${status}`}>{status}</span>
}

function formatLastActive(value: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

export function MemberList() {
  const { data, isLoading, isError, refetch } = useMembersQuery()

  if (isError) {
    return (
      <div className="iam-member-list__error" data-testid="member-list-error">
        <span>Failed to load members.</span>
        <button type="button" onClick={() => void refetch()}>Retry</button>
      </div>
    )
  }

  return (
    <table className="iam-member-list" data-testid="member-list">
      <thead>
        <tr>
          <th>Member</th>
          <th>Role</th>
          <th>Last active</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {isLoading && (
          <tr data-testid="member-list-loading">
            <td colSpan={4} className="iam-member-list__loading">Loading…</td>
          </tr>
        )}
        {!isLoading && data?.items.length === 0 && (
          <tr data-testid="member-list-empty">
            <td colSpan={4} className="iam-member-list__empty">No members yet.</td>
          </tr>
        )}
        {data?.items.map((m) => (
          <tr key={m.id} data-testid={`member-row-${m.id}`}>
            <td>
              <div className="iam-member-cell">
                <Avatar name={m.name} />
                <div>
                  <div className="iam-member-cell__name">{m.name}</div>
                  <div className="iam-member-cell__email">{m.email}</div>
                </div>
              </div>
            </td>
            <td><RoleBadge role={m.role} /></td>
            <td className="iam-member-list__mono">{formatLastActive(m.last_active)}</td>
            <td><StatusCell status={m.status} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
