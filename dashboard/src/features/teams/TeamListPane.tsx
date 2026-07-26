import { bucketForRatio } from '../../components/topology/budgetThreshold'
import { TruthfulValue } from '../../components/truthfulness/TruthfulValue'
import { absent, isKnown, known, type Certain } from '../../lib/truthfulness'
import { budgetBucketColor } from './budgetColor'
import type { TeamListRow } from './api'

interface TeamListPaneProps {
  rows: TeamListRow[]
  selectedId: string | undefined
  onSelect: (teamId: string) => void
  isLoading: boolean
  isError: boolean
  /**
   * How many agents no team claims — or why that is not known. A failed
   * topology request must not render as `0` here: an empty-looking unclaimed
   * chip reads as "everything is governed", which is the one claim this page
   * may never make without evidence (AAASM-5157).
   */
  orphanCount: Certain<number>
  isOrphanSelected: boolean
  onSelectOrphan: () => void
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
export function TeamListPane({
  rows,
  selectedId,
  onSelect,
  isLoading,
  isError,
  orphanCount,
  isOrphanSelected,
  onSelectOrphan,
}: Readonly<TeamListPaneProps>) {
  // `rows` is already `[]` on both failure and first load, so the count has to
  // be recovered from the query state rather than from the array's length.
  let groupCount: Certain<number>
  if (isError) groupCount = absent('unavailable', 'Failed to load teams')
  else if (isLoading) groupCount = absent('unknown', 'Request in flight')
  else groupCount = known(rows.length)

  return (
    <div className="teams-list-pane" data-testid="team-list-pane">
      <div className="teams-list-pane__head">
        <span className="teams-list-pane__title">Agent Groups</span>
        <span className="teams-list-pane__count" data-testid="team-list-count">
          {/* Same rule as the unclaimed chip below: a failed overview must not
              render as "0 groups", which reads as a measured empty org. */}
          <TruthfulValue value={groupCount} testId="team-list-count-value" />
          {' group'}{isKnown(groupCount) && groupCount.value === 1 ? '' : 's'}
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

        {/* Rendered unconditionally: the unclaimed section has its own data
            source, so hiding it behind the team list's loading/error state
            would once again make ungoverned agents unreachable exactly when
            something is wrong. */}
        <div className="teams-list-orphan" data-testid="team-list-orphan-section">
          <div className="teams-list-orphan__label">unclaimed</div>
          <button
            type="button"
            className={`teams-list-row teams-list-orphan__row${isOrphanSelected ? ' is-active' : ''}`}
            data-testid="team-list-orphan-row"
            aria-current={isOrphanSelected}
            onClick={onSelectOrphan}
          >
            <div className="teams-list-row__top">
              <span className="teams-list-row__name">orphan agents</span>
              <span
                className={`teams-chip${isKnown(orphanCount) && orphanCount.value > 0 ? ' is-warn' : ''}`}
                data-testid="team-list-orphan-count"
              >
                <TruthfulValue value={orphanCount} testId="team-list-orphan-count-value" />
              </span>
            </div>
          </button>
        </div>
      </div>
    </div>
  )
}
