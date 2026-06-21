import { useMemo, useState } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { CostBreakdownPanel } from '../features/analytics/CostBreakdownPanel'
import { SegmentedControl } from '../features/analytics/SegmentedControl'
import { TeamBudgetBar } from '../components/topology/TeamBudgetBar'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
} from '../features/teams/api'
import { deriveCostKpis, type BudgetPeriod } from '../features/costs/costKpis'
import '../features/analytics/CostBreakdownPanel.css'
import './CostsPage.css'

const PERIOD_OPTIONS: { value: BudgetPeriod; label: string }[] = [
  { value: 'daily', label: 'Daily' },
  { value: 'monthly', label: 'Monthly' },
]

/** Map a utilisation percentage to its KPI-value severity modifier. */
function utilisationClass(pct: number | null): string {
  if (pct == null) return ''
  if (pct >= 95) return ' costs-kpi__value--danger'
  if (pct >= 80) return ' costs-kpi__value--warn'
  return ' costs-kpi__value--ok'
}

function usd(value: number | null): string {
  return value == null ? '—' : `$${value.toFixed(2)}`
}

interface KpiCardProps {
  readonly label: string
  readonly value: string
  readonly sub: string
  readonly valueClass?: string
  readonly testId: string
}

function KpiCard({ label, value, sub, valueClass = '', testId }: KpiCardProps) {
  return (
    <div className="costs-kpi" data-testid={testId}>
      <div className="costs-kpi__label">{label}</div>
      <div className={`costs-kpi__value${valueClass}`}>{value}</div>
      <div className="costs-kpi__sub">{sub}</div>
    </div>
  )
}

/**
 * Cost & Budget page (AAASM-3509) — replaces the `<ComingSoon>` stub at `/costs`.
 *
 * Composed from existing OSS blocks per design/v1/hi-fi/costs.jsx:
 *   - KPI strip   — derived from `/api/v1/costs` (total spend / top consumer /
 *                   budget utilisation / blocked-by-budget).
 *   - Per-team    — `TeamBudgetBar` over `joinTeamRows(...)`, with a daily/monthly
 *     budget bars   period toggle; the green/amber/red bucket is the shared
 *                   `bucketForBudget` threshold (≥95% = danger/red).
 *   - Per-agent   — the analytics `CostBreakdownPanel` (own filter + query).
 *     breakdown
 *
 * The OSS `/api/v1/costs` summary only carries an *org* budget limit, so per-team
 * utilisation is each team's spend against the org limit (its share of the org
 * budget) rather than a per-team configured limit, which the OSS API does not
 * expose.
 */
export function CostsPage() {
  const [period, setPeriod] = useState<BudgetPeriod>('daily')
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()

  const teamRows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data),
    [overviewQuery.data, costsQuery.data],
  )
  const kpis = useMemo(
    () => deriveCostKpis(costsQuery.data, teamRows, period),
    [costsQuery.data, teamRows, period],
  )

  const isLoading = costsQuery.isLoading || overviewQuery.isLoading
  const isError = costsQuery.isError

  const periodLabel = period === 'daily' ? 'today' : 'this month'

  return (
    <div className="costs-page" data-testid="costs-page">
      <header className="costs-head">
        <div>
          <h1 className="costs-title">Cost &amp; Budget</h1>
          <p className="costs-sub">
            LLM inference spend across all agents — daily / monthly breakdown with configured
            budget limits.
          </p>
        </div>
        <SegmentedControl
          options={PERIOD_OPTIONS}
          value={period}
          onChange={setPeriod}
          testIdPrefix="costs-period"
        />
      </header>

      <div className="costs-kpis" data-testid="costs-kpis">
        <KpiCard
          testId="costs-kpi-total"
          label="Total spend"
          value={usd(kpis.totalSpend)}
          sub={`spend ${periodLabel}`}
        />
        <KpiCard
          testId="costs-kpi-top-consumer"
          label="Top consumer"
          value={kpis.topConsumer?.agentId ?? '—'}
          sub={kpis.topConsumer ? `${usd(kpis.topConsumer.spend)} ${periodLabel}` : 'no spend data'}
        />
        <KpiCard
          testId="costs-kpi-utilisation"
          label="Budget utilisation"
          value={kpis.utilisationPct == null ? 'N/A' : `${kpis.utilisationPct.toFixed(1)}%`}
          sub={kpis.limit == null ? 'no budget limit set' : `of ${usd(kpis.limit)} limit`}
          valueClass={utilisationClass(kpis.utilisationPct)}
        />
        <KpiCard
          testId="costs-kpi-blocked"
          label="Blocked by budget"
          value={String(kpis.blockedByBudget)}
          sub={kpis.blockedByBudget === 0 ? 'no teams over limit' : 'teams at ≥95% of org limit'}
          valueClass={kpis.blockedByBudget > 0 ? ' costs-kpi__value--danger' : ''}
        />
      </div>

      <section className="costs-section" data-testid="costs-team-budgets">
        <div className="costs-section__head">
          <h2 className="costs-section__title">Per-team budget</h2>
          <span className="costs-section__hint">
            {period === 'daily' ? 'daily' : 'monthly'} spend vs org limit · green &lt;80% · amber
            80–95% · red ≥95%
          </span>
        </div>

        {isError ? (
          <p className="costs-state costs-state--error" data-testid="costs-error">
            Failed to load cost data.
            <button
              type="button"
              className="costs-state__retry"
              onClick={() => ignorePromise(costsQuery.refetch())}
            >
              Retry
            </button>
          </p>
        ) : isLoading ? (
          <p className="costs-state" data-testid="costs-loading">
            Loading cost data…
          </p>
        ) : teamRows.length === 0 ? (
          <p className="costs-team-bars__empty" data-testid="costs-team-empty">
            No teams registered yet.
          </p>
        ) : (
          <div className="costs-team-bars">
            {teamRows.map(row => (
              <TeamBudgetBar
                key={row.team_id}
                team={row.team_id}
                spent={row.daily_spend_usd ?? 0}
                limit={row.daily_limit_usd ?? 0}
              />
            ))}
          </div>
        )}
      </section>

      <section className="costs-section" data-testid="costs-breakdown">
        <CostBreakdownPanel />
      </section>
    </div>
  )
}
