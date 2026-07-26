import type { TeamPolicy } from './api'

interface TeamActivePoliciesCardProps {
  policies: TeamPolicy[]
  isLoading: boolean
  isError: boolean
}

/**
 * Active-policies card for the selected team (`design/v1/hi-fi/teams.jsx`).
 *
 * Backed by `GET /api/v1/policies/team/{team_id}` (AAASM-5096): every policy
 * document in force for at least one agent in the team, resolved from the live
 * cascade. The scope chip says which cascade tier each policy comes from, so a
 * fleet-wide `global` document is not mistaken for a team-authored one.
 *
 * `hits24h` folds to `—`, never `0`: no audit record attributes a decision to a
 * policy document today, so the count is absent on the wire and rendering a `0`
 * would read as "this policy never fired" (AAASM-5100 / ADR 0018 owns capturing
 * it).
 */
export function TeamActivePoliciesCard({
  policies,
  isLoading,
  isError,
}: Readonly<TeamActivePoliciesCardProps>) {
  return (
    <section className="teams-card" data-testid="team-policies-card" aria-label="Active policies">
      <div className="teams-card__title">Active policies ({policies.length})</div>

      {isLoading && (
        <div className="teams-card__empty" data-testid="team-policies-loading">
          Loading policies…
        </div>
      )}

      {!isLoading && isError && (
        <div className="teams-card__empty" data-testid="team-policies-error">
          Failed to load policies for this team.
        </div>
      )}

      {!isLoading && !isError && policies.length === 0 && (
        <div className="teams-card__empty" data-testid="team-policies-empty">
          No policy is in force for this team.
        </div>
      )}

      {!isLoading && !isError && policies.length > 0 && (
        <ul className="teams-policy-list" data-testid="team-policies-list">
          {policies.map((policy) => (
            <li key={policy.id} className="teams-policy-row" data-testid="team-policy-row">
              <span className="teams-policy-row__name">{policy.name}</span>
              <span className="teams-chip teams-policy-row__scope" data-testid="team-policy-scope">
                {policy.scope}
              </span>
              <span className="teams-policy-row__hits" data-testid="team-policy-hits">
                {policy.hits24h ?? '—'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
