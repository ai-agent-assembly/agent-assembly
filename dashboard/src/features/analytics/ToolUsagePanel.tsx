import { useMemo } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { useAnalyticsFilters } from './useAnalyticsFilters'
import { useToolUsageQuery } from './useToolUsageQuery'
import { sortToolsByCallsDesc, errorRateColor } from './toolUsageUtils'

export function ToolUsagePanel() {
  const { filters } = useAnalyticsFilters()
  const { data, isPending, isError } = useToolUsageQuery(filters)

  const rawTools = data?.tools
  const tools = useMemo(() => rawTools ?? [], [rawTools])
  const sortedTools = useMemo(() => sortToolsByCallsDesc(tools), [tools])

  return (
    <div className="tool-usage-panel" data-testid="tool-usage-panel">
      <div className="tool-usage-panel__header">
        <h2 className="tool-usage-panel__title">Tool Usage</h2>
      </div>

      {isPending ? (
        <div className="tool-usage-panel__skeleton" aria-hidden />
      ) : isError ? (
        <p className="tool-usage-panel__error">Failed to load tool usage data.</p>
      ) : tools.length === 0 ? (
        <div className="tool-usage-panel__empty">
          <p>No tool calls in the selected window.</p>
        </div>
      ) : (
        <>
          {/* Hidden anchors for testing — recharts SVG is invisible at 0-width in jsdom */}
          {sortedTools.map((tool, idx) => (
            <span
              key={tool.name}
              data-testid={`tool-usage-bar-${tool.name}`}
              data-index={idx}
              aria-hidden
              style={{ display: 'none' }}
            />
          ))}
          <ResponsiveContainer width="100%" height={Math.max(180, sortedTools.length * 36 + 24)}>
          <BarChart
            data={sortedTools}
            layout="vertical"
            margin={{ top: 4, right: 24, left: 8, bottom: 4 }}
          >
            <XAxis
              type="number"
              tick={{ fontSize: 11, fill: 'var(--text-muted)' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={130}
              tick={{ fontSize: 12, fill: 'var(--text-secondary)' }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              formatter={(value: any, name: any) => {
                if (name === 'calls') return [value, 'Calls']
                return [value, name]
              }}
            />
            <Bar dataKey="calls" radius={[0, 3, 3, 0]}>
              {sortedTools.map(tool => (
                <Cell key={tool.name} fill={errorRateColor(tool.errorRate)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        </>
      )}
    </div>
  )
}
