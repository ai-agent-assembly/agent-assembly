import { useAnalyticsFilters } from '../features/analytics/useAnalyticsFilters'
import { FilterBar } from '../features/analytics/FilterBar'
import { useAgentsQuery } from '../features/agents/api'
import { useTeamsQuery } from '../features/analytics/useTeamsQuery'
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
      <div className="analytics-page__panels">
        {/* Chart panels are mounted by subsequent sub-tickets */}
      </div>
    </main>
  )
}
