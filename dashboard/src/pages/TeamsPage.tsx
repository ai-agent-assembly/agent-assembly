import { useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { certainFromQuery, mapCertain } from '../lib/truthfulness'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyAgentsQuery,
  useTopologyOverviewQuery,
} from '../features/teams/api'
import { reconcileAgentCensus, selectOrphanAgents } from '../features/teams/orphans'
import { TeamListPane } from '../features/teams/TeamListPane'
import { TeamDetailPane } from '../features/teams/TeamDetailPane'
import { TeamOrphanDetail } from '../features/teams/TeamOrphanDetail'
import './TeamsPage.css'

// Sentinel selection id for the "unclaimed" orphan section — distinct from any
// real team_id so it can share the single selection state with team rows.
const ORPHAN_ID = '__orphan__'

/**
 * Teams page — two-pane view (AAASM-5044, per `design/v2/hi-fi/teams.jsx`,
 * authoritative under ADR 0025): a selectable team list on the left and the
 * selected team's detail cards (budget usage, approval routing, members) on the
 * right. Assembled entirely from existing endpoints (topology graph, topology
 * overview, cost rollup, budget tree, approvals queue); no new backend surface.
 *
 * Every agent must be reachable from exactly one grouping here — a team row or
 * the unclaimed section. That invariant is the page's whole purpose, so it is
 * cross-checked against the registry's own tally rather than assumed
 * (AAASM-5157).
 */
export function TeamsPage() {
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()
  const agentsQuery = useTopologyAgentsQuery()
  const [picked, setPicked] = useState<string | undefined>(undefined)

  const rows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data),
    [overviewQuery.data, costsQuery.data],
  )

  // Orphans come from the whole fleet, not the overview's root-only
  // `standalone_root_agents` (AAASM-5157) — see `orphans.ts` for why. Kept as a
  // `Certain` all the way to the chip and the pane so a failed topology request
  // renders as "unavailable" rather than as a reassuring `0 unclaimed`.
  const orphans = mapCertain(certainFromQuery(agentsQuery), selectOrphanAgents)
  const census = reconcileAgentCensus(overviewQuery.data, orphans)

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
          orphanCount={mapCertain(orphans, list => list.length)}
          isOrphanSelected={orphanPicked}
          onSelectOrphan={() => setPicked(ORPHAN_ID)}
        />
        {orphanPicked
          ? <TeamOrphanDetail orphans={orphans} census={census} />
          : <TeamDetailPane teamId={selected} />}
      </div>
    </main>
  )
}
