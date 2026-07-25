import { useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
} from '../features/teams/api'
import { TeamListPane } from '../features/teams/TeamListPane'
import { TeamDetailPane } from '../features/teams/TeamDetailPane'
import { TeamOrphanDetail } from '../features/teams/TeamOrphanDetail'
import './TeamsPage.css'

// Sentinel selection id for the "unclaimed" orphan section — distinct from any
// real team_id so it can share the single selection state with team rows.
const ORPHAN_ID = '__orphan__'

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
  const orphans = overviewQuery.data?.standalone_root_agents ?? []

  // Derive the effective selection rather than syncing it into state from an
  // effect: default to the first team until the operator picks one, and fall
  // back to the default if the picked team drops out of the (refetched) list.
  // The orphan section is a valid pick and never drops out, so it short-circuits
  // the team fallback.
  const orphanPicked = picked === ORPHAN_ID
  const pickedExists = picked != null && rows.some(r => r.team_id === picked)
  const selectedTeam = pickedExists ? picked : rows[0]?.team_id
  const selected = orphanPicked ? undefined : selectedTeam

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
          orphanCount={orphans.length}
          isOrphanSelected={orphanPicked}
          onSelectOrphan={() => setPicked(ORPHAN_ID)}
        />
        {orphanPicked ? <TeamOrphanDetail orphans={orphans} /> : <TeamDetailPane teamId={selected} />}
      </div>
    </main>
  )
}
