import type { EnforcementBucket, EnforcementTimeline as EnforcementTimelineData } from '../../features/overview/api'
import './EnforcementTimeline.css'

/**
 * The four verdict lanes rendered by the timeline, in posture order. Colours
 * are theme tokens (not literals) so the chart inverts with `data-theme`,
 * matching the `decisionTone` vocabulary used elsewhere on the Overview page.
 */
type Lane = { key: 'allow' | 'narrow' | 'deny' | 'scrub'; color: string }

const LANES: readonly Lane[] = [
  { key: 'allow', color: 'var(--ok)' },
  { key: 'narrow', color: 'var(--warn)' },
  { key: 'deny', color: 'var(--danger)' },
  { key: 'scrub', color: 'var(--scrub)' },
]

/**
 * One lane's mini bar chart: a vertical bar per bucket, height proportional to
 * the lane's own maximum so every lane reveals its shape (mirrors the hi-fi
 * `MiniBar`). `max` is floored at 1 to avoid a divide-by-zero on an all-zero
 * lane.
 */
function MiniBar({ values, color }: Readonly<{ values: number[]; color: string }>) {
  const max = Math.max(1, ...values)
  const barW = 6
  const step = 8
  const height = 28
  const usable = height - 2
  return (
    <svg
      className="etl-bar"
      viewBox={`0 0 ${Math.max(1, values.length) * step} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-hidden="true"
    >
      {values.map((v, i) => {
        const h = (v / max) * usable
        return <rect key={i} x={i * step} y={height - h} width={barW} height={h} fill={color} />
      })}
    </svg>
  )
}

/** Evenly-spaced time-axis tick labels derived from the bucket timestamps. */
function axisTicks(buckets: EnforcementBucket[], window: string): string[] {
  if (buckets.length === 0) return []
  const format = (ms: number) => {
    const d = new Date(ms)
    return window === '7d' || window === '30d'
      ? d.toLocaleDateString([], { month: 'numeric', day: 'numeric' })
      : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }
  const idxs = [0, Math.floor(buckets.length / 4), Math.floor(buckets.length / 2), Math.floor((buckets.length * 3) / 4)]
  return [...idxs.map((i) => format(buckets[i].ts)), 'now']
}

/**
 * Overview POSTURE enforcement timeline: a stacked mini-bar chart of
 * allow/narrow/deny/scrub decision counts over the selected window, with a
 * legend and a time axis. Presentational — the parent owns the query so it can
 * be spied in tests; renders honest loading/error/empty states rather than a
 * fabricated series.
 */
export function EnforcementTimeline({
  window,
  data,
  isLoading,
  isError,
}: Readonly<{ window: string; data: EnforcementTimelineData | undefined; isLoading: boolean; isError: boolean }>) {
  const buckets = data?.buckets ?? []
  const total = buckets.reduce((sum, b) => sum + b.allow + b.narrow + b.deny + b.scrub, 0)

  return (
    <section className="overview-card enforcement-timeline" data-testid="overview-enforcement-timeline">
      <div className="etl-head">
        <div className="overview-card__label">▤ enforcement timeline · {window}</div>
        <div className="etl-legend">
          {LANES.map((lane) => (
            <span key={lane.key} className="etl-legend__item" style={{ color: lane.color }}>
              ● {lane.key}
            </span>
          ))}
        </div>
      </div>
      {isLoading ? (
        <p className="overview-empty-note" data-testid="overview-enforcement-timeline-loading">
          Loading enforcement timeline…
        </p>
      ) : isError ? (
        <p className="overview-empty-note" data-testid="overview-enforcement-timeline-error">
          Enforcement timeline unavailable.
        </p>
      ) : total === 0 ? (
        <p className="overview-empty-note" data-testid="overview-enforcement-timeline-empty">
          No enforcement decisions in this window.
        </p>
      ) : (
        <>
          <div className="etl-grid" data-testid="overview-enforcement-timeline-chart">
            {LANES.map((lane) => (
              <div className="etl-row" key={lane.key}>
                <div className="etl-row__label">{lane.key}</div>
                <MiniBar values={buckets.map((b) => b[lane.key])} color={lane.color} />
              </div>
            ))}
          </div>
          <div className="etl-axis">
            {axisTicks(buckets, window).map((tick, i) => (
              <span key={i}>{tick}</span>
            ))}
          </div>
        </>
      )}
    </section>
  )
}
