import { Link, useNavigate } from 'react-router-dom'
import { ignorePromise } from '../lib/ignorePromise'
import { useActiveSessionsQuery } from '../features/agents/api'
import { elapsedLabel } from '../features/agents/sessionTime'
import { StatusChip } from '../components/fleet/StatusChip'

const SKELETON_ROW_KEYS = Array.from({ length: 4 }, (_, i) => `sess-skeleton-${i}`)
const SKELETON_CELL_KEYS = Array.from({ length: 5 }, (_, j) => `sess-skeleton-cell-${j}`)

/**
 * Fleet → Active Sessions tab (AAASM-5038): a fleet-wide, read-only table of
 * currently-open agent sessions served by `GET /api/v1/fleet/active-sessions`.
 *
 * The design mock's `current task` / `actions` columns are intentionally absent:
 * the gateway registry tracks session id, start, and status per session but not
 * a per-session action count or task label, and this surface only shows state
 * that already exists rather than inventing it.
 */
export function ActiveSessionsView() {
  const navigate = useNavigate()
  const { data: sessions, isLoading, isError, refetch } = useActiveSessionsQuery()

  if (isError) {
    return (
      <div className="fleet-error" data-testid="sessions-error">
        <span>Failed to load active sessions.</span>
        <button type="button" onClick={() => ignorePromise(refetch())}>Retry</button>
      </div>
    )
  }

  if (!isLoading && (sessions?.length ?? 0) === 0) {
    return (
      <p className="fleet-empty fleet-empty--inline" data-testid="sessions-empty">
        No active sessions right now. Sessions appear here while agents are running.
      </p>
    )
  }

  return (
    <div className="fleet-table__wrap">
      <table className="fleet-table" data-testid="sessions-table">
        <thead>
          <tr>
            <th className="fleet-table__th">session</th>
            <th className="fleet-table__th">agent</th>
            <th className="fleet-table__th">running</th>
            <th className="fleet-table__th">status</th>
            <th className="fleet-table__th" aria-label="actions" />
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            SKELETON_ROW_KEYS.map((rowKey) => (
              <tr key={rowKey} data-testid="session-row-skeleton">
                {SKELETON_CELL_KEYS.map((cellKey) => (
                  <td key={cellKey} className="fleet-table__cell fleet-table__cell--skeleton">
                    <span className="fleet-table__skeleton" />
                  </td>
                ))}
              </tr>
            ))
          ) : (
            (sessions ?? []).map((s) => (
              <tr
                key={s.session_id}
                data-testid="session-row"
                className="fleet-table__row"
                onClick={() => navigate(`/agents/${s.agent_id}`)}
              >
                <td className="fleet-table__cell">
                  <span className="fleet-session__id">{s.session_id}</span>
                </td>
                <td className="fleet-table__cell">
                  <Link
                    to={`/agents/${s.agent_id}`}
                    className="fleet-session__agent"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {s.agent_name}
                  </Link>
                  {s.team_id && <span className="fleet-session__team">{s.team_id}</span>}
                </td>
                <td className="fleet-table__cell">
                  <span className="fleet-session__running">
                    <span className="fleet-session__pulse" aria-hidden="true" />
                    {elapsedLabel(s.started_at)}
                  </span>
                </td>
                <td className="fleet-table__cell">
                  <StatusChip status={s.status} />
                </td>
                <td className="fleet-table__cell">
                  <Link
                    to={`/agents/${s.agent_id}`}
                    className="fleet-session__inspect"
                    onClick={(e) => e.stopPropagation()}
                  >
                    inspect →
                  </Link>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
