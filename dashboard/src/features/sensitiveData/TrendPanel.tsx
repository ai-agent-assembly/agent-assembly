/**
 * The counters over time (AAASM-5360).
 *
 * ## Why a table and not a line chart
 *
 * Two things the surface must keep visible are hard to keep visible in one
 * series: a bucket's **action** count and its **finding** count are different
 * measures, and an empty bucket is a real answer that must not be interpolated
 * across. The API already emits zeroed buckets "so a chart shows a gap rather
 * than joining across it"; a table shows the gap as a row with an explicit `0`
 * and its unit, and gives both measures their own labelled column, which no
 * single-axis chart does without a legend the reader has to trust.
 *
 * The bars are a within-column comparison against that column's own maximum, not
 * a shared scale: comparing an action count against a finding count visually
 * would be exactly the conflation this Epic exists to prevent. Each bar is drawn
 * beside the number it scales, never instead of it, and a zero draws no bar at
 * all rather than a minimum-width sliver.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { CountFigure } from './CountFigure'
import { barPercent, formatDuration, formatInstantNs } from './format'
import { countMeasure, readResult, resultDescription, resultTitle } from './measures'
import type { SensitiveDataTimeseriesResponse } from './schema'
import './sensitiveData.css'

export interface TrendPanelProps {
  readonly timeseries: Certain<SensitiveDataTimeseriesResponse>
  /** How many narrowing predicates are in force, for the empty-state copy. */
  readonly activeFilterCount: number
}

export function TrendPanel({ timeseries, activeFilterCount }: Readonly<TrendPanelProps>) {
  if (!isKnown(timeseries)) {
    return (
      <section className="sd-panel" data-testid="sd-trend">
        <StatusState
          state={timeseries.state}
          title="The trend could not be read"
          description="No series is drawn. A flat line at zero would be indistinguishable from a quiet week."
          detail={timeseries.detail}
          testId="sd-trend-absent"
        />
      </section>
    )
  }

  const { points, bucket_seconds: bucketSeconds } = timeseries.value
  const totalEvents = points.reduce((sum, point) => sum + point.counters.event_count, 0)
  const maxEvents = Math.max(0, ...points.map((p) => p.counters.event_count))
  const maxFindings = Math.max(0, ...points.map((p) => p.counters.finding_count))

  return (
    <section className="sd-panel" data-testid="sd-trend">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Over time</h2>
        <span className="sd-measure__description">{formatDuration(bucketSeconds)} buckets</span>
      </div>

      {totalEvents === 0 ? (
        <StatusState
          state={null}
          title={resultTitle(readResult(0, activeFilterCount))}
          description={resultDescription(readResult(0, activeFilterCount))}
          testId="sd-trend-empty"
        />
      ) : (
        <div className="sd-table__scroll">
          <table className="sd-table" data-testid="sd-trend-table">
            <caption className="sd-panel__note">
              Each row is one {formatDuration(bucketSeconds)} bucket. Actions and findings are
              counted separately and their bars are scaled within their own column, so the two are
              never compared to each other by eye.
            </caption>
            <thead>
              <tr>
                <th scope="col">Bucket start (UTC)</th>
                <th scope="col">Actions with findings</th>
                <th scope="col" className="sd-bar-cell">
                  <span className="sd-sr-only">Actions, relative</span>
                </th>
                <th scope="col">Findings</th>
                <th scope="col" className="sd-bar-cell">
                  <span className="sd-sr-only">Findings, relative</span>
                </th>
                <th scope="col">Actions blocked</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.start_ns} data-testid={`sd-trend-row-${point.start_ns}`}>
                  <td>{formatInstantNs(point.start_ns)}</td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('event_count', point.counters)}
                      inline
                      testId={`sd-trend-events-${point.start_ns}`}
                    />
                  </td>
                  <td>
                    <span
                      className="sd-bar"
                      style={{ width: `${barPercent(point.counters.event_count, maxEvents)}%` }}
                      aria-hidden
                    />
                  </td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('finding_count', point.counters)}
                      inline
                      testId={`sd-trend-findings-${point.start_ns}`}
                    />
                  </td>
                  <td>
                    <span
                      className="sd-bar sd-bar--finding"
                      style={{
                        width: `${barPercent(point.counters.finding_count, maxFindings)}%`,
                      }}
                      aria-hidden
                    />
                  </td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('blocked_event_count', point.counters)}
                      inline
                      testId={`sd-trend-blocked-${point.start_ns}`}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
