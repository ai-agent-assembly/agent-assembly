import type { ApiKey } from './types'
import './IdentityDetailCard.css'

interface IdentityDetailCardProps {
  identity: ApiKey
  /** Closes the detail card; ServiceIdentitiesPanel clears `selected`. */
  onClose: () => void
}

function formatTimestamp(value: string): string {
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return value
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

/**
 * Per-identity detail card for the Service Identities tab (AAASM-1396).
 * Surfaces the six profile fields named in AAASM-119 implementation rule 2 +
 * AC #5:
 *   1. Service ID (prefix; the secret never leaves the create-time reveal)
 *   2. Owner
 *   3. Role
 *   4. Assigned Policies
 *   5. Current Permissions (the row's `scopes` — most operators read this
 *      column as "what can this key call")
 *   6. Recent Activity (last N events for this identity)
 *
 * Pairs with `<ServiceIdentitiesPanel>`'s 2-column layout — list on the
 * left, this card on the right — mirroring `<RolesPermissionsPanel>`.
 */
export function IdentityDetailCard({ identity, onClose }: IdentityDetailCardProps) {
  return (
    <aside
      className="iam-identity-detail-card"
      data-testid="identity-detail-card"
      data-identity-id={identity.id}
      aria-label={`Identity detail: ${identity.label}`}
    >
      <header className="iam-identity-detail-card__head">
        <div>
          <div className="iam-identity-detail-card__eyebrow">service identity</div>
          <h3 className="iam-identity-detail-card__title">{identity.label}</h3>
        </div>
        <button
          type="button"
          className="iam-identity-detail-card__close"
          data-testid="identity-detail-card-close"
          aria-label="Close detail card"
          onClick={onClose}
        >
          ✕
        </button>
      </header>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-service-id"
      >
        <div className="iam-identity-detail-card__section-label">Service ID</div>
        <div className="iam-identity-detail-card__section-value" data-testid="identity-detail-service-id">
          <code>{identity.prefix}</code>
        </div>
      </section>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-owner"
      >
        <div className="iam-identity-detail-card__section-label">Owner</div>
        <div className="iam-identity-detail-card__section-value" data-testid="identity-detail-owner">
          {identity.owner}
        </div>
      </section>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-role"
      >
        <div className="iam-identity-detail-card__section-label">Role</div>
        <div className="iam-identity-detail-card__section-value" data-testid="identity-detail-role">
          {identity.role}
        </div>
      </section>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-policies"
      >
        <div className="iam-identity-detail-card__section-label">Assigned Policies</div>
        {identity.assigned_policies.length === 0 ? (
          <div className="iam-identity-detail-card__empty" data-testid="identity-detail-policies-empty">
            No policies assigned yet.
          </div>
        ) : (
          <ul className="iam-identity-detail-card__chips" data-testid="identity-detail-policies">
            {identity.assigned_policies.map((p) => (
              <li key={p} className="iam-scope-chip" data-testid="identity-detail-policy">
                {p}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-permissions"
      >
        <div className="iam-identity-detail-card__section-label">Current Permissions</div>
        {identity.scopes.length === 0 ? (
          <div className="iam-identity-detail-card__empty" data-testid="identity-detail-permissions-empty">
            No scopes granted.
          </div>
        ) : (
          <ul className="iam-identity-detail-card__chips" data-testid="identity-detail-permissions">
            {identity.scopes.map((s) => (
              <li key={s} className="iam-scope-chip" data-testid="identity-detail-permission">
                {s}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section
        className="iam-identity-detail-card__section"
        data-testid="identity-detail-section-activity"
      >
        <div className="iam-identity-detail-card__section-label">Recent Activity</div>
        {identity.recent_activity.length === 0 ? (
          <div className="iam-identity-detail-card__empty" data-testid="identity-detail-activity-empty">
            No recent activity.
          </div>
        ) : (
          <ul className="iam-identity-detail-card__activity" data-testid="identity-detail-activity">
            {identity.recent_activity.map((e) => (
              <li
                key={e.id}
                className="iam-identity-detail-card__activity-row"
                data-testid="identity-detail-activity-entry"
              >
                <span className="iam-identity-detail-card__activity-time">
                  {formatTimestamp(e.timestamp)}
                </span>
                <span className="iam-identity-detail-card__activity-action">{e.action}</span>
                <span className="iam-identity-detail-card__activity-target">{e.target}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </aside>
  )
}
