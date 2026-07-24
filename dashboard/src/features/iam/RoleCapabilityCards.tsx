import { useMembersQuery } from './api'
import { buildRoleCards, type RoleCard } from './roleCapabilities'
import type { Member, Role } from './types'
import './RoleCapabilityCards.css'

const ROLE_BADGE_TONE: Record<Role, string> = {
  Owner: 'iam-role-badge--owner',
  Admin: 'iam-role-badge--admin',
  Member: 'iam-role-badge--member',
  Viewer: 'iam-role-badge--viewer',
}

function firstName(name: string): string {
  return name.trim().split(/\s+/)[0] || name
}

function initial(name: string): string {
  return name.trim().charAt(0).toUpperCase() || '?'
}

function CapabilityList({ card }: Readonly<{ card: RoleCard }>) {
  if (card.capabilities.length === 0) {
    return (
      <p className="role-card__placeholder" data-testid={`role-card-caps-empty-${card.role}`}>
        Capability grants for this role are not yet available.
      </p>
    )
  }
  return (
    <div className="role-card__caps" data-testid={`role-card-caps-${card.role}`}>
      {card.capabilities.map((cap) => (
        <span key={cap} className="role-card__cap">
          {cap}
        </span>
      ))}
    </div>
  )
}

function Assignees({ assignees }: Readonly<{ assignees: Member[] }>) {
  if (assignees.length === 0) return null
  return (
    <>
      <div className="role-card__section-title">assigned</div>
      <div className="role-card__assignees">
        {assignees.map((m) => (
          <div key={m.id} className="role-card__assignee" data-testid={`role-card-assignee-${m.id}`}>
            <span className="iam-avatar role-card__avatar" aria-hidden="true">
              {initial(m.name)}
            </span>
            <span className="role-card__assignee-name">{firstName(m.name)}</span>
          </div>
        ))}
      </div>
    </>
  )
}

export function RoleCapabilityCard({ card }: Readonly<{ card: RoleCard }>) {
  const memberLabel = `${card.memberCount} member${card.memberCount === 1 ? '' : 's'}`
  return (
    <article className="role-card" data-testid={`role-card-${card.role}`}>
      <header className="role-card__header">
        <span className={`iam-role-badge ${ROLE_BADGE_TONE[card.role]}`}>{card.role}</span>
        <span className="role-card__count" data-testid={`role-card-count-${card.role}`}>
          {memberLabel}
        </span>
      </header>

      {card.description ? (
        <p className="role-card__desc">{card.description}</p>
      ) : (
        <p className="role-card__placeholder">No description available for this role.</p>
      )}

      <div className="role-card__section-title">capabilities</div>
      <CapabilityList card={card} />

      <Assignees assignees={card.assignees} />
    </article>
  )
}

/**
 * Grid of role-capability cards for the Identity → Roles tab
 * (design/v1/hi-fi/identity.jsx RolesTab). Member counts / assignees are live
 * IAM data; capability grants come from the static built-in catalogue — see
 * the flag banner and `roleCapabilities.ts` for why they are not yet live.
 */
export function RoleCapabilityCards() {
  const { data, isLoading, isError } = useMembersQuery()
  const cards = buildRoleCards(data?.items ?? [])

  return (
    <section className="role-cards" data-testid="role-capability-cards">
      <header className="role-cards__header">
        <h3 className="role-cards__title">Built-in roles</h3>
        <p className="role-cards__sub">
          The capabilities each built-in role grants, and the members currently assigned to it.
        </p>
      </header>

      <p className="role-cards__flag" data-testid="role-cards-grant-flag">
        Capability grants shown are the documented built-in defaults. Live per-tenant grants
        appear once the gateway exposes a role → capability endpoint.
      </p>

      {isError && (
        <p className="role-cards__error" data-testid="role-cards-error">
          Member assignments could not be loaded; showing grants only.
        </p>
      )}
      {isLoading && (
        <p className="role-cards__loading" data-testid="role-cards-loading">
          Loading role assignments…
        </p>
      )}

      <div className="role-cards__grid">
        {cards.map((card) => (
          <RoleCapabilityCard key={card.role} card={card} />
        ))}
      </div>
    </section>
  )
}
