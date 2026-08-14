import type { TeamPolicy } from './api'

interface TeamActivePoliciesCardProps {
  /** `null` when the API could not resolve the mapping — see `CardState`. */
  policies: TeamPolicy[] | null
  isLoading: boolean
  isError: boolean
}

/**
 * What the card can truthfully say, in priority order. Split out of the JSX so
 * the mutually-exclusive states are decided once, in one place, instead of as a
 * chain of `!isLoading && !isError && …` guards that has to be re-read to prove
 * two of them cannot render together.
 */
type CardState = 'loading' | 'error' | 'unknown' | 'none' | 'list'

function cardState(policies: TeamPolicy[] | null, isLoading: boolean, isError: boolean): CardState {
  if (isLoading) return 'loading'
  if (isError) return 'error'
  if (policies == null) return 'unknown'
  return policies.length === 0 ? 'none' : 'list'
}

/**
 * Active-policies card for the selected team (`design/v1/hi-fi/teams.jsx`).
 *
 * Backed by `GET /api/v1/policies/team/{team_id}` (AAASM-5096): every policy
 * document in force for at least one agent in the team, resolved from the live
 * cascade. The scope chip says which cascade tier each policy comes from, so a
 * fleet-wide `global` document is not mistaken for a team-authored one.
 *
 * Three empty-ish states, deliberately worded differently, because each is a
 * different claim:
 *
 * * `unknown` (`policies === null`) — the API could not resolve the mapping.
 *   Says "Policy data unavailable", the same way the Policy list's reach column
 *   folds to `—` rather than to "0 agents". This is the state of every shipped
 *   deployment until the policy cascade is wired (AAASM-5106): a policy *is*
 *   being enforced from the engine's primary slot, so claiming otherwise would
 *   be a false governance statement.
 * * `none` (`policies === []`) — the team has no agent for a policy to be in
 *   force over. The only case where "no policy is in force" is true.
 * * `error` — the request failed; also not a governance claim.
 *
 * `hits24h` folds to `—`, never `0`: no audit record attributes a decision to a
 * policy document today, so the count is absent on the wire and rendering a `0`
 * would read as "this policy never fired" (AAASM-5107 owns capturing it).
 */
export function TeamActivePoliciesCard({
  policies,
  isLoading,
  isError,
}: Readonly<TeamActivePoliciesCardProps>) {
  const state = cardState(policies, isLoading, isError)

  return (
    <section className="teams-card" data-testid="team-policies-card" aria-label="Active policies">
      <div className="teams-card__title">Active policies ({policies?.length ?? '—'})</div>

      {state === 'loading' && (
        <div className="teams-card__empty" data-testid="team-policies-loading">
          Loading policies…
        </div>
      )}

      {state === 'error' && (
        <div className="teams-card__empty" data-testid="team-policies-error">
          Failed to load policies for this team.
        </div>
      )}

      {state === 'unknown' && (
        <div className="teams-card__empty" data-testid="team-policies-unknown">
          Policy data unavailable — the policy cascade is not currently loaded.
        </div>
      )}

      {state === 'none' && (
        <div className="teams-card__empty" data-testid="team-policies-empty">
          No policy is in force for this team.
        </div>
      )}

      {state === 'list' && (
        <ul className="teams-policy-list" data-testid="team-policies-list">
          {policies?.map((policy) => (
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
