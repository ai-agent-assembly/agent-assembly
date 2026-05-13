import { useMemo, useState } from 'react'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { usePolicyEffectivenessQuery } from './usePolicyEffectivenessQuery'
import {
  computeRatio,
  computeRowTotals,
  sortRulesByBlocks,
  collectDates,
  ratioToColor,
} from './policyEffectivenessUtils'
import type { PolicyDay } from './policyEffectivenessUtils'

interface TooltipState {
  ruleId: string
  ruleName: string
  day: PolicyDay
  x: number
  y: number
}

const DATE_FMT = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' })

function formatDate(iso: string): string {
  return DATE_FMT.format(new Date(iso))
}

export function PolicyEffectivenessPanel() {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = usePolicyEffectivenessQuery(filters)

  const [sortAsc, setSortAsc] = useState(false)
  const [tooltip, setTooltip] = useState<TooltipState | null>(null)

  const rawRules = data?.rules
  const rules = useMemo(() => rawRules ?? [], [rawRules])
  const totals = useMemo(() => computeRowTotals(rules), [rules])
  const sortedRules = useMemo(() => sortRulesByBlocks(rules, totals, sortAsc), [rules, totals, sortAsc])
  const dates = useMemo(() => collectDates(rules), [rules])

  const dayMap = useMemo(() => {
    const m = new Map<string, Map<string, PolicyDay>>()
    for (const rule of rules) {
      const byDate = new Map<string, PolicyDay>()
      for (const d of rule.days) byDate.set(d.date, d)
      m.set(rule.id, byDate)
    }
    return m
  }, [rules])

  return (
    <div className="policy-effectiveness-panel" data-testid="policy-effectiveness-panel">
      <div className="policy-effectiveness-panel__header">
        <h2 className="policy-effectiveness-panel__title">Policy Effectiveness</h2>
      </div>

      {isPending ? (
        <div className="policy-effectiveness-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="policy-effectiveness-panel__error">Failed to load policy data.</p>
      ) : rules.length === 0 ? (
        <div className="policy-effectiveness-panel__empty">
          <p>No policies are enabled for the selected filters.</p>
          <a href="/policy/builder">Go to Policy Builder</a>
        </div>
      ) : (
        <div className="policy-effectiveness-panel__scroll">
          <div
            className="policy-effectiveness-panel__grid"
            style={{
              gridTemplateColumns: `180px repeat(${dates.length}, minmax(28px, 1fr))`,
            }}
            role="grid"
            aria-label="Policy effectiveness heatmap"
          >
            {/* Header row */}
            <div className="policy-effectiveness-panel__header-cell">
              <button
                type="button"
                className="policy-effectiveness-panel__sort-btn"
                onClick={() => setSortAsc(p => !p)}
                aria-label={`Sort by blocks ${sortAsc ? 'descending' : 'ascending'}`}
              >
                Rule {sortAsc ? '↑' : '↓'}
              </button>
            </div>
            {dates.map(date => (
              <div key={date} className="policy-effectiveness-panel__date-cell" title={date}>
                {formatDate(date)}
              </div>
            ))}

            {/* Data rows */}
            {sortedRules.map(rule => (
              <>
                <div
                  key={`label-${rule.id}`}
                  className="policy-effectiveness-panel__rule-label"
                  title={rule.name}
                >
                  {rule.name}
                </div>
                {dates.map(date => {
                  const day = dayMap.get(rule.id)?.get(date) ?? {
                    date,
                    blocks: 0,
                    warns: 0,
                    passes: 0,
                  }
                  const ratio = computeRatio(day)
                  const bg = ratioToColor(ratio)
                  return (
                    <div
                      key={`cell-${rule.id}-${date}`}
                      className="policy-effectiveness-panel__cell"
                      style={{ background: bg }}
                      data-testid={`policy-heatmap-cell-${rule.id}-${date}`}
                      data-ratio={ratio.toFixed(4)}
                      role="gridcell"
                      aria-label={`${rule.name} ${date}: ${day.blocks} blocks, ${day.warns} warns, ${day.passes} passes`}
                      onMouseEnter={e => {
                        const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
                        setTooltip({ ruleId: rule.id, ruleName: rule.name, day, x: rect.left, y: rect.top })
                      }}
                      onMouseLeave={() => setTooltip(null)}
                    />
                  )
                })}
              </>
            ))}
          </div>

          {/* Hover tooltip */}
          {tooltip && (
            <div
              className="policy-effectiveness-panel__tooltip"
              style={{ left: tooltip.x, top: tooltip.y }}
              role="tooltip"
            >
              <strong>{tooltip.ruleName}</strong>
              <span>{tooltip.day.date}</span>
              <span>Blocks: {tooltip.day.blocks}</span>
              <span>Warns: {tooltip.day.warns}</span>
              <span>Passes: {tooltip.day.passes}</span>
              <span>
                Ratio:{' '}
                {(computeRatio(tooltip.day) * 100).toFixed(1)}%
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
