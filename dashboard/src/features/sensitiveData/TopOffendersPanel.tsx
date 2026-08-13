/**
 * The worst agents, tools or destinations, with a trend (AAASM-5360).
 *
 * ## Why grouping by an agent is right here and wrong on the breakdown
 *
 * ADR 0032 §9 forbids `agent_id` and `destination` as *metric labels* because a
 * label multiplies time series without bound. This route is not a time series:
 * it is a ranked list over the queryable event store, which is exactly where §9
 * sends those dimensions, and it returns a bounded number of rows by
 * construction. The two panels therefore offer different controls on purpose,
 * and the note says so — otherwise the next reader "fixes" the inconsistency.
 *
 * ## `new` is not `up from zero`
 *
 * The API distinguishes a first appearance from a rise, and so does this table:
 * an agent that was absent from the preceding window is a different operator
 * signal from one whose count went up, and rendering both as an upward arrow
 * loses the distinction the backend went to the trouble of keeping.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { CountFigure } from './CountFigure'
import { formatInstantNs } from './format'
import { countMeasure, formatCount, readResult, resultDescription, resultTitle } from './measures'
import type { OffenderDimension } from './api'
import { OFFENDER_DIMENSIONS } from './api'
import type { TopOffendersResponse, TrendDirection } from './schema'
import './sensitiveData.css'

const DIMENSION_LABELS = new Map<OffenderDimension, string>([
  ['agent', 'Acting agent'],
  ['root_agent', 'Root agent'],
  ['tool', 'Tool'],
  ['destination', 'Destination'],
])

const TREND_LABELS = new Map<TrendDirection, string>([
  ['up', 'Up'],
  ['down', 'Down'],
  ['flat', 'Unchanged'],
  // Not "up from zero": absent from the preceding window entirely.
  ['new', 'First appearance'],
])

export interface TopOffendersPanelProps {
  readonly offenders: Certain<TopOffendersResponse>
  readonly dimension: OffenderDimension
  readonly onDimensionChange: (dimension: OffenderDimension) => void
  readonly activeFilterCount: number
}

export function TopOffendersPanel({
  offenders,
  dimension,
  onDimensionChange,
  activeFilterCount,
}: Readonly<TopOffendersPanelProps>) {
  return (
    <section className="sd-panel" data-testid="sd-offenders">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Top offenders</h2>
        <label className="sd-field">
          Rank by
          <select
            data-testid="sd-offenders-dimension"
            value={dimension}
            onChange={(event) => onDimensionChange(event.target.value as OffenderDimension)}
          >
            {OFFENDER_DIMENSIONS.map((value) => (
              <option key={value} value={value}>
                {DIMENSION_LABELS.get(value) ?? value}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="sd-panel__note">
        A ranked list over the event store, not a time series — which is why it may rank by agent
        and destination where the breakdown may not. The change column compares against the window
        of the same length immediately before this one.
      </p>

      {!isKnown(offenders) ? (
        <StatusState
          state={offenders.state}
          title="The ranking could not be read"
          description="No ranking is shown. An empty table here would read as “no agent triggered anything”."
          detail={offenders.detail}
          testId="sd-offenders-absent"
        />
      ) : offenders.value.entries.length === 0 ? (
        <StatusState
          state={null}
          title={resultTitle(readResult(0, activeFilterCount))}
          description={resultDescription(readResult(0, activeFilterCount))}
          testId="sd-offenders-empty"
        />
      ) : (
        <div className="sd-table__scroll">
          <table className="sd-table" data-testid="sd-offenders-table">
            <caption className="sd-panel__note">
              Compared against {formatInstantNs(offenders.value.comparison_from_ns)} →{' '}
              {formatInstantNs(offenders.value.comparison_to_ns)}.
            </caption>
            <thead>
              <tr>
                <th scope="col">{DIMENSION_LABELS.get(dimension) ?? dimension}</th>
                <th scope="col">Findings</th>
                <th scope="col">Actions with findings</th>
                <th scope="col">Actions blocked</th>
                <th scope="col">Change in findings</th>
              </tr>
            </thead>
            <tbody>
              {offenders.value.entries.map((entry) => (
                <tr key={entry.key} data-testid={`sd-offender-row-${entry.key}`}>
                  <td>{entry.key}</td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('finding_count', entry.counters)}
                      inline
                      testId={`sd-offender-findings-${entry.key}`}
                    />
                  </td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('event_count', entry.counters)}
                      inline
                      testId={`sd-offender-events-${entry.key}`}
                    />
                  </td>
                  <td className="sd-num">
                    <CountFigure
                      measure={countMeasure('blocked_event_count', entry.counters)}
                      inline
                      testId={`sd-offender-blocked-${entry.key}`}
                    />
                  </td>
                  <td className="sd-num">
                    <span
                      className={`sd-trend sd-trend--${entry.trend}`}
                      data-testid={`sd-offender-trend-${entry.key}`}
                      data-trend={entry.trend}
                    >
                      {TREND_LABELS.get(entry.trend) ?? entry.trend}
                    </span>{' '}
                    <span className="sd-figure__unit">
                      {entry.trend === 'new'
                        ? `no findings in the preceding window`
                        : `${entry.finding_count_delta >= 0 ? '+' : '−'}${formatCount(
                            Math.abs(entry.finding_count_delta),
                          )} findings`}
                    </span>
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
