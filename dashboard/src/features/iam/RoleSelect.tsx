import { useUpdateMemberRoleMutation } from './api'
import { useToast } from '../../components/Toast'
import { ROLES, type Member, type Role } from './types'

export interface RoleSelectProps {
  member: Member
  onBeforeChange?: (member: Member, next: Role) => boolean | Promise<boolean>
}

export function RoleSelect({ member, onBeforeChange }: RoleSelectProps) {
  const { mutate, isPending } = useUpdateMemberRoleMutation()
  const { toast } = useToast()

  async function handleChange(event: React.ChangeEvent<HTMLSelectElement>) {
    const next = event.target.value as Role
    if (next === member.role) return
    if (onBeforeChange) {
      const proceed = await onBeforeChange(member, next)
      if (!proceed) return
    }
    mutate(
      { id: member.id, role: next },
      {
        onError: (err) => {
          toast(err instanceof Error ? err.message : 'Failed to update role', 'error')
        },
      },
    )
  }

  return (
    <select
      data-testid={`role-select-${member.id}`}
      value={member.role}
      onChange={handleChange}
      disabled={isPending}
      aria-label={`Change role for ${member.name}`}
    >
      {ROLES.map((r) => (
        <option key={r} value={r}>{r}</option>
      ))}
    </select>
  )
}
