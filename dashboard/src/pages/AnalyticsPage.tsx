import { useAnalyticsFilters } from '../features/analytics/useAnalyticsFilters'
import { FilterBar } from '../features/analytics/FilterBar'
import { KpiStrip } from '../features/analytics/KpiStrip'
import { ActionVolumePanel } from '../features/analytics/ActionVolumePanel'
import { CostBreakdownPanel } from '../features/analytics/CostBreakdownPanel'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
import '../features/analytics/KpiStrip.css'
import '../features/analytics/ActionVolumePanel.css'
import '../features/analytics/CostBreakdownPanel.css'
import './AnalyticsPage.css'

export function AnalyticsPage() {
  const { filters, setFilters } = useAnalyticsFilters()
  const agentsQuery = useAgentsQuery()
  const teamsQuery = useTeamsQuery()

  return (
    <main className="analytics-page">
      <h1>Analytics</h1>
      <FilterBar
        filters={filters}
        onFiltersChange={setFilters}
        agents={agentsQuery.data ?? []}
        teams={teamsQuery.data ?? []}
        isLoadingAgents={agentsQuery.isPending}
        isLoadingTeams={teamsQuery.isPending}
      />
      <KpiStrip />
      <div className="analytics-page__panels">
        <ActionVolumePanel />
        <CostBreakdownPanel />
        {/* Remaining chart panels mounted by subsequent sub-tickets */}
      </div>
    </main>
  )
}
