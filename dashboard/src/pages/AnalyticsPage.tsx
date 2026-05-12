import { useAnalyticsFilters } from '../features/analytics/useAnalyticsFilters'
import { FilterBar } from '../features/analytics/FilterBar'
import './AnalyticsPage.css'

export function AnalyticsPage() {
  const { filters, setFilters } = useAnalyticsFilters()

  return (
    <main className="analytics-page">
      <h1>Analytics</h1>
      <FilterBar filters={filters} onFiltersChange={setFilters} />
      <div className="analytics-page__panels">
        {/* Chart panels are mounted by subsequent sub-tickets */}
      </div>
    </main>
  )
}
