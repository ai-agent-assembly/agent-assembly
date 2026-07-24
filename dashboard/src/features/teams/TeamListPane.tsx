import { bucketForRatio } from '../../components/topology/budgetThreshold'
import { budgetBucketColor } from './budgetColor'
import type { TeamListRow } from './api'

interface TeamListPaneProps {
  rows: TeamListRow[]
  selectedId: string | undefined
  onSelect: (teamId: string) => void
  isLoading: boolean
  isError: boolean
}

function MiniBudgetBar({ pct }: Readonly<{ pct: number }>) {
  const color = budgetBucketColor(bucketForRatio(pct / 100))
  return (
    <div>
      <div className="teams-mini-bar">
        <div className="teams-mini-bar__fill" style={{ width: `${Math.min(100, pct)}%`, background: color }} />
      </div>
      <div className="teams-mini-bar__label">{pct.toFixed(1)}% burn</div>
    </div>
  )
}

/**
 * Left pane of the two-pane Teams view: the selectable team list. Rows are the
 * already-joined topology + cost rollup (`joinTeamRows`), so each carries its
 * agent count and daily burn-against-org-limit for the mini budget bar.
 */
export function TeamListPane({ rows, selectedId, onSelect, isLoading, isError }: Readonly<TeamListPaneProps>) {
  return (
    <div className="teams-list-pane" data-testid="team-list-pane">
      <div className="teams-list-pane__head">
        <span className="teams-list-pane__title">Agent Groups</span>
        <span className="teams-list-pane__count" data-testid="team-list-count">
          {rows.length} group{rows.length === 1 ? '' : 's'}
        </span>
        <button
          type="button"
          className="teams-list-pane__new"
          data-testid="team-list-new"
          disabled
          title="Creating agent groups is available in Agent Assembly Cloud"
        >
          + New
        </button>
      </div>

      <div className="teams-list-pane__scroll">
        {isLoading && (
          <div className="teams-card__empty" style={{ padding: '0.75rem 0.875rem' }} data-testid="team-list-loading">
            Loading teams…
          </div>
        )}

        {!isLoading && isError && (
          <div className="teams-card__empty" style={{ padding: '0.75rem 0.875rem' }} data-testid="team-list-error">
            Failed to load teams.
          </div>
        )}

        {!isLoading && !isError && rows.length === 0 && (
          <div className="teams-card__empty" style={{ padding: '0.75rem 0.875rem' }} data-testid="team-list-empty">
            No teams registered yet.
          </div>
        )}

        {rows.map(row => (
          <button
            key={row.team_id}
            type="button"
            className={`teams-list-row${row.team_id === selectedId ? ' is-active' : ''}`}
            data-testid="team-list-row"
            data-team={row.team_id}
            aria-current={row.team_id === selectedId}
            onClick={() => onSelect(row.team_id)}
          >
            <div className="teams-list-row__top">
              <span className="teams-list-row__name">{row.team_id}</span>
              <span className="teams-list-row__agents">{row.agent_count}×</span>
            </div>
            {row.burn_pct != null && <MiniBudgetBar pct={row.burn_pct} />}
          </button>
        ))}
      </div>
    </div>
  )
}
