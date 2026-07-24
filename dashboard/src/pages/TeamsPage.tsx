import { useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
} from '../features/teams/api'
import { TeamListPane } from '../features/teams/TeamListPane'
import { TeamDetailPane } from '../features/teams/TeamDetailPane'
import './TeamsPage.css'

/**
 * Teams page — two-pane view (AAASM-5044, per `design/v1/hi-fi/teams.jsx`):
 * a selectable team list on the left and the selected team's detail cards
 * (budget usage, approval routing, members) on the right. Assembled entirely
 * from existing endpoints (topology overview, cost rollup, budget tree,
 * approvals queue); no new backend surface.
 */
export function TeamsPage() {
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()
  const [picked, setPicked] = useState<string | undefined>(undefined)

  const rows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data),
    [overviewQuery.data, costsQuery.data],
  )

  // Derive the effective selection rather than syncing it into state from an
  // effect: default to the first team until the operator picks one, and fall
  // back to the default if the picked team drops out of the (refetched) list.
  const pickedExists = picked != null && rows.some(r => r.team_id === picked)
  const selected = pickedExists ? picked : rows[0]?.team_id

  const isError = overviewQuery.isError

  return (
    <main>
      {isError && (
        <div
          data-testid="teams-error"
          style={{ color: 'var(--status-danger-solid)', padding: '0.75rem 1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <span>Failed to load teams.</span>
          <button type="button" onClick={() => ignorePromise(overviewQuery.refetch())}>Retry</button>
        </div>
      )}

      <div className="teams-two-pane" data-testid="teams-two-pane">
        <TeamListPane
          rows={rows}
          selectedId={selected}
          onSelect={setPicked}
          isLoading={overviewQuery.isLoading}
          isError={isError}
        />
        <TeamDetailPane teamId={selected} />
      </div>
    </main>
  )
}
