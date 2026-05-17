import { useState } from 'react'
import { CURRENT_USER_ID, useInviteMemberMutation, useMembersQuery } from './api'
import { ConfirmRoleChangeModal } from './ConfirmRoleChangeModal'
import { detectDangerousRoleChange, type DangerousRoleChange } from './dangerousRoleChange'
import { InviteMemberDialog } from './InviteMemberDialog'
import { MemberList } from './MemberList'
import { useToast } from '../../components/Toast'
import type { InviteMemberInput, Member, Role } from './types'
import './MembersPanel.css'

interface PendingChange {
  member: Member
  nextRole: Role
  /** Null for safe changes — modal still opens but renders a neutral message
   *  (AAASM-1400: always confirm role changes, expanding the AAASM-1084 gate). */
  danger: DangerousRoleChange | null
  resolve: (proceed: boolean) => void
}

export function MembersPanel() {
  const [inviteOpen, setInviteOpen] = useState(false)
  const [pending, setPending] = useState<PendingChange | null>(null)
  const invite = useInviteMemberMutation()
  const { data: page } = useMembersQuery()
  const { toast } = useToast()

  function handleBeforeRoleChange(member: Member, nextRole: Role): Promise<boolean> {
    // AAASM-1400 — always open the confirm modal. The danger detector now
    // shapes the message (danger reason vs neutral confirmation), but no
    // role change applies inline. Parent Story AAASM-119 AC #3 wants every
    // role change gated behind an explicit confirm step.
    const danger = detectDangerousRoleChange(member, nextRole, {
      allMembers: page?.items ?? [],
      currentUserId: CURRENT_USER_ID,
    })
    return new Promise<boolean>((resolve) => {
      setPending({ member, nextRole, danger, resolve })
    })
  }

  function resolvePending(proceed: boolean) {
    if (!pending) return
    pending.resolve(proceed)
    setPending(null)
  }

  function handleInvite(input: InviteMemberInput) {
    invite.mutate(input, {
      onSuccess: (member) => {
        setInviteOpen(false)
        toast(`Invitation sent to ${member.email}`, 'success')
      },
      onError: (err) => {
        toast(err instanceof Error ? err.message : 'Failed to send invitation', 'error')
      },
    })
  }

  return (
    <section className="iam-members-panel" data-testid="iam-panel-members">
      <header className="iam-members-panel__header">
        <h2>Members</h2>
        <button
          type="button"
          className="iam-members-panel__invite-btn"
          data-testid="invite-member-button"
          onClick={() => setInviteOpen(true)}
        >
          Invite member
        </button>
      </header>

      <MemberList onBeforeRoleChange={handleBeforeRoleChange} />

      <InviteMemberDialog
        open={inviteOpen}
        onClose={() => setInviteOpen(false)}
        onSubmit={handleInvite}
        isSubmitting={invite.isPending}
      />

      <ConfirmRoleChangeModal
        open={pending !== null}
        member={pending?.member ?? null}
        nextRole={pending?.nextRole ?? null}
        danger={pending?.danger ?? null}
        onCancel={() => resolvePending(false)}
        onConfirm={() => resolvePending(true)}
      />
    </section>
  )
}
