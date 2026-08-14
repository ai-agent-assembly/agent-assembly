import type { CostHistory } from '../../features/costs/api'
import './HistoryChart.css'

/** Strip the year from a `YYYY-MM-DD` date, matching the hi-fi `MM-DD` axis. */
function shortDate(date: string): string {
  const parts = date.split('-')
  return parts.length === 3 ? `${parts[1]}-${parts[2]}` : date
}

const VIEW_W = 560
const VIEW_H = 90

/**
 * 7-day spend-history bar chart (AAASM-5032). One bar per day, height
 * proportional to that day's spend against the window maximum; the most recent
 * day is emphasised with the `--ink` token so "today" reads at a glance.
 * Presentational — the parent owns the query so it can be spied in tests — and
 * renders honest loading / error / empty states rather than a fabricated series.
 * Colours are theme tokens so the chart inverts with `data-theme`.
 */
export function HistoryChart({
  data,
  isLoading,
  isError,
}: Readonly<{ data: CostHistory | undefined; isLoading: boolean; isError: boolean }>) {
  const points = data?.points ?? []
  const spends = points.map(p => Number.parseFloat(p.spend_usd) || 0)
  const total = spends.reduce((sum, v) => sum + v, 0)
  const max = Math.max(1, ...spends)

  const n = points.length
  const barW = n > 0 ? Math.min(52, (VIEW_W / n) * 0.7) : 0
  const gap = n > 0 ? (VIEW_W - barW * n) / (n + 1) : 0

  let body
  if (isLoading) {
    body = (
      <p className="history-chart__note" data-testid="costs-history-loading">
        Loading spend history…
      </p>
    )
  } else if (isError) {
    body = (
      <p className="history-chart__note" data-testid="costs-history-error">
        Spend history unavailable.
      </p>
    )
  } else if (n === 0 || total === 0) {
    body = (
      <p className="history-chart__note" data-testid="costs-history-empty">
        No spend recorded in this window.
      </p>
    )
  } else {
    body = (
      <svg
        className="history-chart__svg"
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label="Daily spend for the last 7 days"
        data-testid="costs-history-chart"
      >
        {points.map((p, i) => {
          const h = Math.max(4, (spends[i] / max) * (VIEW_H - 26))
          const x = gap + i * (barW + gap)
          const y = VIEW_H - 18 - h
          const last = i === n - 1
          return (
            <g key={p.date} className={last ? 'history-chart__col--last' : 'history-chart__col'}>
              <rect x={x} y={y} width={barW} height={h} rx="2" className="history-chart__bar" />
              <text x={x + barW / 2} y={VIEW_H - 4} textAnchor="middle" className="history-chart__date">
                {shortDate(p.date)}
              </text>
              <text x={x + barW / 2} y={y - 4} textAnchor="middle" className="history-chart__value">
                ${spends[i].toFixed(0)}
              </text>
            </g>
          )
        })}
      </svg>
    )
  }

  return (
    <section className="history-chart" data-testid="costs-history">
      <div className="history-chart__title">7-day spend history</div>
      {body}
    </section>
  )
}
