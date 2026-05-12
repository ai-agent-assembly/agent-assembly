import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useKpiQuery } from './useKpiQuery'
import { KpiCard } from './KpiCard'
import type { KpiMetric } from './kpi-delta'

interface KpiConfig {
  metric: KpiMetric
  label: string
  unit?: string
}

const KPI_CONFIGS: KpiConfig[] = [
  { metric: 'agents',      label: 'Total Agents' },
  { metric: 'invocations', label: 'Total Invocations' },
  { metric: 'p99',         label: 'p99 Latency', unit: 'ms' },
  { metric: 'cost',        label: 'Total Cost',  unit: 'USD' },
  { metric: 'anomalies',   label: 'Anomaly Count' },
]

function KpiCardConnected({ metric, label, unit }: KpiConfig) {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = useKpiQuery(metric, filters)
  return (
    <KpiCard
      metric={metric}
      label={label}
      unit={unit}
      value={data?.value}
      delta={data?.delta}
      isLoading={isPending}
      isError={isError}
    />
  )
}

export function KpiStrip() {
  return (
    <div className="kpi-strip">
      {KPI_CONFIGS.map(cfg => (
        <KpiCardConnected key={cfg.metric} {...cfg} />
      ))}
    </div>
  )
}
