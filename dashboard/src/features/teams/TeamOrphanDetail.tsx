import { Link } from 'react-router-dom'
import { StatusState } from '../../components/truthfulness/StatusState'
import { TruthfulValue } from '../../components/truthfulness/TruthfulValue'
import { isKnown, mapCertain, type Certain } from '../../lib/truthfulness'
import type { AgentNode } from './api'
import type { AgentCensus } from './orphans'
import { statusChip } from './statusChip'

interface TeamOrphanDetailProps {
  /**
   * Every agent no team claims, at any delegation depth — or why that set is
   * not known. Never a bare array: "we could not fetch the fleet" and "no agent
   * is ungoverned" are opposite governance claims and must not share a shape.
   */
  orphans: Certain<readonly AgentNode[]>
  /** Groupings-vs-registry cross-check; see {@link AgentCensus}. */
  census: Certain<AgentCensus>
  /**
   * Whether the caller's scope can observe unclaimed agents at all (AAASM-5183).
   * A team-scoped caller structurally cannot see `team_id: None` agents, so when
   * this is `false` the pane must say "not available in your scope" rather than
   * render an empty list as a confident "no unclaimed agents" — a governance
   * claim that scope cannot support. No count is shown in that case either.
   */
  unclaimedObservable: boolean
}

/**
 * Count chip for a set whose size may not be known.
 *
 * Pluralisation has to follow the *known* count, so it lives here rather than
 * being interpolated next to a `—`, where "— agents" would read as a measured
 * plural.
 */
function OrphanCountChip({ orphans }: Readonly<{ orphans: Certain<readonly AgentNode[]> }>) {
  const count = mapCertain(orphans, list => list.length)
  return (
    <span className="teams-chip" data-testid="orphan-detail-agent-count">
      <TruthfulValue value={count} testId="orphan-detail-agent-count-value" />
      {/* `.teams-chip` is a flex container, which strips the whitespace of a
          bare text node; the unit needs its own box to keep its space. */}
      <span className="teams-chip__unit"> agent{isKnown(count) && count.value === 1 ? '' : 's'}</span>
    </span>
  )
}

/**
 * The page's own consistency check, surfaced instead of resolved.
 *
 * The wording reports the disagreement and stops there, deliberately. "Some
 * agents are not reachable" would be a stronger claim than the evidence
 * supports: the two figures come from separate responses, so a delegation spawn
 * landing between them produces exactly the same arithmetic as a genuinely
 * hidden agent. Asserting the hidden-agent reading would put a false sentence on
 * a governance surface during ordinary product behaviour — the same failure
 * class this page was fixed to remove. The operator gets both figures and is
 * told what the view cannot determine.
 */
function CensusNotice({ census }: Readonly<{ census: Certain<AgentCensus> }>) {
  if (!isKnown(census) || census.value.unaccountedFor === 0) return null
  const { grouped, total, unaccountedFor } = census.value
  const gap = Math.abs(unaccountedFor)
  return (
    <StatusState
      state="unknown"
      testId="orphan-census-mismatch"
      title={`Agent totals disagree by ${gap}`}
      description={
        'These groupings and the registry were read from separate responses and report different totals. '
        + 'That is either a snapshot taken mid-change or agents this page cannot reach; this view cannot tell which. '
        + 'Reload to see whether it settles.'
      }
      detail={`${grouped} grouped here vs ${total} reported by the registry.`}
    />
  )
}

/**
 * Detail pane shown when the "unclaimed" orphan section is selected.
 *
 * An orphan is an agent no team claims — at *any* delegation depth. The earlier
 * root-only definition (`standalone_root_agents`, `depth == 0`) left spawned
 * ungoverned agents in no grouping at all (AAASM-5157).
 *
 * The point of this view is the governance callout: unlike a team, an orphan
 * agent has no team-scoped policy or budget, so it runs in whatever mode it
 * registered with. No budget/approval/members cards apply here (there is no
 * team to scope them to), so this is intentionally a lighter view than
 * `TeamDetailPane`.
 */
export function TeamOrphanDetail({ orphans, census, unclaimedObservable }: Readonly<TeamOrphanDetailProps>) {
  const list = isKnown(orphans) ? orphans.value : []
  const suspendedCount = list.filter(a => a.status === 'suspended').length
  const flaggedCount = list.filter(a => a.flagged).length

  return (
    <div className="teams-detail-pane" data-testid="orphan-detail-pane">
      <header className="teams-detail-header" data-testid="orphan-detail-header">
        <div className="teams-detail-header__eyebrow">unclaimed</div>
        <h2 className="teams-detail-header__name">orphan agents</h2>
        <div className="teams-detail-header__chips">
          {/* AAASM-5183: only show a count when the caller could actually observe
              unclaimed agents. Out of scope → a "n/a" chip, never a "0". */}
          {unclaimedObservable ? (
            <OrphanCountChip orphans={orphans} />
          ) : (
            <span className="teams-chip" data-testid="orphan-detail-agent-count">
              <span className="teams-chip__unit">not in scope</span>
            </span>
          )}
          {suspendedCount > 0 && (
            <span className="teams-chip is-warn">{suspendedCount} suspended</span>
          )}
          {flaggedCount > 0 && (
            <span className="teams-chip is-danger">{flaggedCount} flagged</span>
          )}
        </div>
      </header>

      <div className="teams-detail-cards">
        <div className="teams-callout is-danger" data-testid="orphan-detail-callout" role="note">
          <div className="teams-callout__title">No governance applied</div>
          Orphan agents have no team assignment and no policy scoped to them. They run in
          whatever enforcement mode was set at registration. Assign them to a team or apply an
          agent-scoped policy.
        </div>

        <CensusNotice census={census} />

        <section className="teams-card" aria-label="Orphan agents">
          <div className="teams-card__title">
            {/* AAASM-5183: no parenthesised count when the scope can't observe
                unclaimed agents — "Agents (0)" would be a false clean reading. */}
            Agents{unclaimedObservable && (
              <> (<TruthfulValue value={mapCertain(orphans, l => l.length)} testId="orphan-agents-title-count" />)</>
            )}
          </div>
          {!isKnown(orphans) && (
            <StatusState
              state={orphans.state}
              testId="orphan-agents-absent"
              title="Unclaimed agents could not be listed"
              description="Until the fleet loads, this page cannot say whether any agent is ungoverned."
              detail={orphans.detail}
            />
          )}
          {isKnown(orphans) && list.length === 0 && !unclaimedObservable && (
            // AAASM-5183: the caller's scope cannot see `team_id: None` agents, so
            // an empty list here is not evidence there are none — it's the scope
            // boundary. Say that, don't claim a clean fleet.
            <StatusState
              state="not-supported"
              testId="orphan-agents-out-of-scope"
              title="Unclaimed agents are not available in your current scope"
              description="Your scope only covers agents assigned to your team, so this page cannot see agents that no team claims. Ask an operator with fleet-wide scope to review unclaimed agents."
            />
          )}
          {isKnown(orphans) && list.length === 0 && unclaimedObservable && (
            <div className="teams-card__empty" data-testid="orphan-agents-empty">
              No unclaimed agents.
            </div>
          )}
          {list.length > 0 && (
            <div data-testid="orphan-agents-list">
              {list.map(agent => (
                <div key={agent.id} className="teams-member-row" data-testid="orphan-agent-row">
                  <div className="teams-member-avatar" aria-hidden="true">{agent.name.charAt(0)}</div>
                  <div className="teams-member-row__main">
                    <Link
                      to={`/agents/${encodeURIComponent(agent.id)}`}
                      className="teams-member-row__name"
                    >
                      {agent.name}
                    </Link>
                    <span className="teams-member-row__meta">depth {agent.depth} · {agent.mode}</span>
                  </div>
                  {agent.flagged && (
                    <span className="teams-chip is-danger" data-testid="orphan-agent-flagged">flagged</span>
                  )}
                  <span className={`teams-chip ${statusChip(agent.status) ?? ''}`} data-testid="orphan-agent-status">
                    {agent.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
