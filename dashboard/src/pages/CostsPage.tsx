import { useMemo, useState, type ReactNode } from 'react'
import { ignorePromise } from '../lib/ignorePromise'
import { CostBreakdownPanel } from '../features/analytics/CostBreakdownPanel'
import { SegmentedControl } from '../features/analytics/SegmentedControl'
import { TeamBudgetBar } from '../components/topology/TeamBudgetBar'
import {
  joinTeamRows,
  useCostSummaryQuery,
  useTopologyOverviewQuery,
  type TeamListRow,
} from '../features/teams/api'
import { useTopologyQuery } from '../features/topology/api'
import { deriveCostKpis, type BudgetPeriod, type PeriodSpend } from '../features/costs/costKpis'
import { buildPerAgentRows } from '../features/costs/perAgentRows'
import { useCostHistoryQuery, useBudgetTreeQuery } from '../features/costs/api'
import { HistoryChart } from '../components/costs/HistoryChart'
import { BudgetTree } from '../components/costs/BudgetTree'
import { BudgetBar } from '../components/costs/BudgetBar'
import { BurnCallouts } from '../components/costs/BurnCallouts'
import { CostTabs, type CostTab } from '../components/costs/CostTabs'
import { PerAgentTable } from '../components/costs/PerAgentTable'
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

/**
 * Burn-value severity for the Daily / Monthly cards — like `utilisationClass`
 * but with no green "ok" band: below 80% the figure stays neutral ink, matching
 * the mock's `kpiColor` (danger ≥95, warn ≥80, else ink).
 */
function burnValueClass(pct: number | null): string {
  if (pct == null) return ''
  if (pct >= 95) return ' costs-kpi__value--danger'
  if (pct >= 80) return ' costs-kpi__value--warn'
  return ''
}

function usd(value: number | null): string {
  return value == null ? '—' : `$${value.toFixed(2)}`
}

interface KpiCardProps {
  readonly label: string
  readonly value: string
  readonly sub: string
  readonly valueClass?: string
  readonly footer?: ReactNode
  readonly testId: string
}

function KpiCard({ label, value, sub, valueClass = '', footer, testId }: KpiCardProps) {
  return (
    <div className="costs-kpi" data-testid={testId}>
      <div className="costs-kpi__label">{label}</div>
      <div className={`costs-kpi__value${valueClass}`}>{value}</div>
      <div className="costs-kpi__sub">{sub}</div>
      {footer}
    </div>
  )
}

interface SpendKpiCardProps {
  readonly label: string
  readonly period: string
  readonly spend: PeriodSpend
  readonly testId: string
}

/** Daily / Monthly spend card: value, "of $limit" sub, mini budget bar + % used. */
function SpendKpiCard({ label, period, spend, testId }: SpendKpiCardProps) {
  return (
    <KpiCard
      testId={testId}
      label={label}
      value={usd(spend.spend)}
      valueClass={burnValueClass(spend.pct)}
      sub={spend.limit == null ? `no ${period} limit set` : `of ${usd(spend.limit)} ${period} limit`}
      footer={
        <div className="costs-kpi__bar">
          <BudgetBar used={spend.spend ?? 0} limit={spend.limit} label={`${period} budget burn`} />
          {spend.pct != null && <div className="costs-kpi__used">{spend.pct.toFixed(1)}% used</div>}
        </div>
      }
    />
  )
}

interface TeamBudgetContentProps {
  readonly isError: boolean
  readonly isLoading: boolean
  readonly teamRows: readonly TeamListRow[]
  readonly onRetry: () => void
}

/**
 * Resolve the per-team budget section body for the current query state.
 *
 * Extracted from the JSX as an explicit if/else chain (rather than a nested
 * ternary) so each error / loading / empty / list branch reads on its own.
 */
function TeamBudgetContent({ isError, isLoading, teamRows, onRetry }: TeamBudgetContentProps): ReactNode {
  if (isError) {
    return (
      <p className="costs-state costs-state--error" data-testid="costs-error">
        Failed to load cost data.{' '}
        <button type="button" className="costs-state__retry" onClick={onRetry}>
          Retry
        </button>
      </p>
    )
  }
  if (isLoading) {
    return (
      <p className="costs-state" data-testid="costs-loading">
        Loading cost data…
      </p>
    )
  }
  if (teamRows.length === 0) {
    return (
      <p className="costs-team-bars__empty" data-testid="costs-team-empty">
        No teams registered yet.
      </p>
    )
  }
  return (
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
  )
}

/**
 * Cost & Budget page (AAASM-3509, restructured for FE parity in AAASM-5076) —
 * replaces the `<ComingSoon>` stub at `/costs`.
 *
 * Composed from existing OSS blocks per design/v1/hi-fi/costs.jsx:
 *   - KPI strip   — Daily / Monthly spend (each with a mini budget bar), Agents
 *                   tracked, plus the live Budget-utilisation and Blocked-by-budget
 *                   KPIs (a superset of the mock's four cards).
 *   - Callouts    — daily-burn warning (≥80%) / critical (≥95%) banners.
 *   - History     — 7-day spend `HistoryChart`.
 *   - Tabs        — Per-agent (table + analytics breakdown) / Per-team (budget
 *                   bars) / Budget tree (inheritance), replacing the previous
 *                   stacked sections.
 *
 * The OSS `/api/v1/costs` summary only carries an *org* budget limit, so per-team
 * utilisation is each team's spend against the org limit (its share of the org
 * budget) rather than a per-team configured limit, which the OSS API does not
 * expose. The mock's per-agent 7-day sparkline and per-team monthly limit are
 * omitted — neither has a backing endpoint yet (AAASM-5076).
 */
export function CostsPage() {
  const [period, setPeriod] = useState<BudgetPeriod>('daily')
  const [tab, setTab] = useState<CostTab>('agents')
  const overviewQuery = useTopologyOverviewQuery()
  const costsQuery = useCostSummaryQuery()
  const topologyQuery = useTopologyQuery()

  const teamRows = useMemo(
    () => joinTeamRows(overviewQuery.data, costsQuery.data),
    [overviewQuery.data, costsQuery.data],
  )
  const kpis = useMemo(
    () => deriveCostKpis(costsQuery.data, teamRows, period),
    [costsQuery.data, teamRows, period],
  )

  // Agent → team map for the per-agent table, resolved from the topology graph
  // (the cost summary's per-agent rows carry no team). Best-effort: agents with
  // no known team render a dash rather than blocking the table.
  const agentTeams = useMemo(() => {
    const map = new Map<string, string>()
    for (const node of topologyQuery.data?.nodes ?? []) {
      if (node.team) map.set(node.id, node.team)
    }
    return map
  }, [topologyQuery.data])
  const perAgentRows = useMemo(
    () => buildPerAgentRows(costsQuery.data, agentTeams),
    [costsQuery.data, agentTeams],
  )

  const historyQuery = useCostHistoryQuery(7)
  const budgetTreeQuery = useBudgetTreeQuery()

  const isLoading = costsQuery.isLoading || overviewQuery.isLoading
  const isError = costsQuery.isError

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
        <SpendKpiCard testId="costs-kpi-daily" label="Daily spend" period="daily" spend={kpis.daily} />
        <SpendKpiCard
          testId="costs-kpi-monthly"
          label="Monthly spend"
          period="monthly"
          spend={kpis.monthly}
        />
        <KpiCard
          testId="costs-kpi-agents"
          label="Agents tracked"
          value={String(kpis.agentsTracked)}
          sub={`across ${kpis.teamsTracked} ${kpis.teamsTracked === 1 ? 'team' : 'teams'}`}
        />
        <KpiCard
          testId="costs-kpi-utilisation"
          label="Budget utilisation"
          value={kpis.utilisationPct == null ? 'N/A' : `${kpis.utilisationPct.toFixed(1)}%`}
          sub={
            kpis.limit == null
              ? 'no budget limit set'
              : `${period === 'daily' ? 'daily' : 'monthly'} · of ${usd(kpis.limit)} limit`
          }
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

      <BurnCallouts dailyPct={kpis.daily.pct} dailyLimit={kpis.daily.limit} />

      <HistoryChart
        data={historyQuery.data}
        isLoading={historyQuery.isLoading}
        isError={historyQuery.isError}
      />

      <CostTabs
        value={tab}
        onChange={setTab}
        agentCount={kpis.agentsTracked}
        teamCount={teamRows.length}
      />

      {tab === 'agents' && (
        <>
          <section className="costs-section" data-testid="costs-agents">
            <PerAgentTable rows={perAgentRows} />
          </section>
          <section className="costs-section" data-testid="costs-breakdown">
            <CostBreakdownPanel />
          </section>
        </>
      )}

      {tab === 'teams' && (
        <section className="costs-section" data-testid="costs-team-budgets">
          <div className="costs-section__head">
            <h2 className="costs-section__title">Per-team budget</h2>
            <span className="costs-section__hint">
              {period === 'daily' ? 'daily' : 'monthly'} spend vs org limit · green &lt;80% · amber
              80–95% · red ≥95%
            </span>
          </div>
          <TeamBudgetContent
            isError={isError}
            isLoading={isLoading}
            teamRows={teamRows}
            onRetry={() => ignorePromise(costsQuery.refetch())}
          />
        </section>
      )}

      {tab === 'tree' && (
        <section className="costs-section" data-testid="costs-budget-tree">
          <div className="costs-section__head">
            <h2 className="costs-section__title">Budget inheritance</h2>
            <span className="costs-section__hint">
              org → team → agent · subtree spend vs each level's limit
            </span>
          </div>
          <BudgetTree
            data={budgetTreeQuery.data}
            isLoading={budgetTreeQuery.isLoading}
            isError={budgetTreeQuery.isError}
          />
        </section>
      )}
    </div>
  )
}
