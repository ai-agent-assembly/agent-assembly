/**
 * AAASM-1055 (F100) — Subtree budget-burn stacked-area chart.
 *
 * Consumes `GET /api/v1/agents/{id}/subtree-burn` (preview endpoint that
 * currently returns a single data point for today; the chart renders
 * whatever `points.length` is). One `<Area>` per direct child stacks the
 * per-child contributions; the tooltip shows child name, period spend,
 * and the percent of subtree total for that day.
 */
import { useMemo, useState } from 'react'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useAgentSubtreeBurnQuery, type BurnPeriod, type SubtreeBurn } from '../features/agents/api'
import { LoadingState } from './LoadingState'
import { ErrorState } from './ErrorState'
import './SubtreeBurnChart.css'

// A stable rotating palette so each child gets a deterministic color across renders.
const PALETTE = ['#4f9aff', '#ffb84d', '#8fd673', '#e57373', '#bf83ff', '#6cc4d6', '#d6d65a'] as const

type ChartRow = {
  date: string
  total: number
  // Per-child spent_usd, keyed by stable id so Recharts can pick it up.
  [childId: string]: string | number
}

export function SubtreeBurnChart({ agentId }: { agentId: string }) {
  const [period, setPeriod] = useState<BurnPeriod>('7d')
  const { data, isLoading, isError, refetch } = useAgentSubtreeBurnQuery(agentId, period)

  const { rows, childIds, childName, childColor } = useMemo(() => transform(data), [data])

  if (isLoading) {
    return (
      <div className="sbc" data-testid="subtree-burn-loading">
        <LoadingState page="generic" />
      </div>
    )
  }

  if (isError || !data) {
    return (
      <div className="sbc" data-testid="subtree-burn-error">
        <ErrorState onRetry={() => void refetch()} />
      </div>
    )
  }

  if (rows.length === 0) {
    return (
      <div className="sbc sbc--empty" data-testid="subtree-burn-empty">
        <p className="sbc__empty-title">No subtree spend recorded yet</p>
        <p className="sbc__empty-body">
          This agent and its direct descendants have no recorded spend for the requested window.
        </p>
      </div>
    )
  }

  return (
    <section className="sbc" data-testid="subtree-burn-chart">
      <header className="sbc__head">
        <div>
          <h3 className="sbc__title">Budget burn · subtree</h3>
          <p className="sbc__subtitle">
            Stacked spend by direct child — preview: showing today only until the daily history
            store lands.
          </p>
        </div>
        <div className="sbc__period" role="group" aria-label="Burn period">
          {(['7d', '30d'] as const).map((p) => (
            <button
              key={p}
              type="button"
              className={`sbc__period-btn${p === period ? ' sbc__period-btn--active' : ''}`}
              onClick={() => setPeriod(p)}
              data-testid={`subtree-burn-period-${p}`}
              aria-pressed={p === period}
            >
              {p}
            </button>
          ))}
        </div>
      </header>

      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={rows} margin={{ top: 12, right: 16, left: 8, bottom: 8 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--line-2)" />
          <XAxis dataKey="date" stroke="var(--ink-4)" fontSize={11} />
          <YAxis stroke="var(--ink-4)" fontSize={11} tickFormatter={formatUsd} />
          <Tooltip content={<BurnTooltip childName={childName} />} />
          {childIds.map((cid) => (
            <Area
              key={cid}
              type="monotone"
              dataKey={cid}
              stackId="subtree"
              stroke={childColor(cid)}
              fill={childColor(cid)}
              fillOpacity={0.6}
              name={childName.get(cid) ?? cid}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </section>
  )
}

function transform(data: SubtreeBurn | undefined): {
  rows: ChartRow[]
  childIds: string[]
  childName: Map<string, string>
  childColor: (cid: string) => string
} {
  const childIds = new Set<string>()
  const childName = new Map<string, string>()

  for (const point of data?.points ?? []) {
    for (const child of point.per_child) {
      childIds.add(child.child_agent_id)
      childName.set(child.child_agent_id, child.child_name)
    }
  }

  const sortedChildIds = Array.from(childIds).sort()

  const rows: ChartRow[] = (data?.points ?? []).map((point) => {
    const row: ChartRow = { date: point.date, total: parseFloat(point.total_usd) || 0 }
    for (const cid of sortedChildIds) {
      const match = point.per_child.find((c) => c.child_agent_id === cid)
      row[cid] = match ? parseFloat(match.spent_usd) || 0 : 0
    }
    return row
  })

  const childColor = (cid: string): string => {
    const idx = sortedChildIds.indexOf(cid)
    return PALETTE[idx % PALETTE.length]
  }

  return { rows, childIds: sortedChildIds, childName, childColor }
}

function formatUsd(value: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(value)
}

interface TooltipPayloadEntry {
  readonly dataKey: string
  readonly value: number
  readonly color: string
}

interface BurnTooltipProps {
  readonly active?: boolean
  readonly payload?: ReadonlyArray<TooltipPayloadEntry>
  readonly label?: string
  readonly childName: Map<string, string>
}

function BurnTooltip({ active, payload, label, childName }: BurnTooltipProps) {
  if (!active || !payload || payload.length === 0) return null
  const total = payload.reduce((acc, p) => acc + (p.value ?? 0), 0)

  return (
    <div className="sbc__tooltip" data-testid="subtree-burn-tooltip">
      <p className="sbc__tooltip-date">{label}</p>
      <ul className="sbc__tooltip-rows">
        {payload.map((p) => {
          const name = childName.get(p.dataKey) ?? p.dataKey
          const pct = total > 0 ? Math.round((p.value / total) * 100) : 0
          return (
            <li key={p.dataKey} className="sbc__tooltip-row">
              <span className="sbc__tooltip-swatch" style={{ background: p.color }} />
              <span className="sbc__tooltip-name">{name}</span>
              <span className="sbc__tooltip-value">
                {formatUsd(p.value)} · {pct}%
              </span>
            </li>
          )
        })}
      </ul>
      <p className="sbc__tooltip-total">Total: {formatUsd(total)}</p>
    </div>
  )
}

export default SubtreeBurnChart
