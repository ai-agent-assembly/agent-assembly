/**
 * Findings grouped by one bounded dimension (AAASM-5360).
 *
 * ## Why the grouping control offers exactly six options
 *
 * ADR 0032 §9 bounds metric labels to `category`, `severity`, `confidence_band`,
 * `outcome`, `detection_method` and `provider_id`. `agent_id`, `destination`,
 * `session_id`, `trace_id` and any fingerprint are forbidden **as labels**
 * because each one multiplies the series; the API refuses them with a `400` that
 * names the six. Offering a seventh option here would build a control whose only
 * outcome is an error, so the control is the enum.
 *
 * Those dimensions are not lost — they are filters and drill-down columns, and
 * `TopOffendersPanel` ranks by them over the event store, which is where §9
 * sends them.
 *
 * ## Both counts, again
 *
 * `DimensionBucket` carries `finding_count` **and** a distinct-by-event
 * `event_count`, and the API's own doc notes the second is "frequently smaller
 * than `finding_count`, and never the same measure". Both are rendered, each
 * with its unit; a single "count" column would silently pick one.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { barPercent } from './format'
import { formatCount, measureUnitNoun, readResult, resultDescription, resultTitle } from './measures'
import { GROUP_BY_DIMENSIONS, dimensionLabel } from './dimensions'
import type { DimensionBucket, MetricDimension, SensitiveDataBreakdownResponse } from './schema'
import './sensitiveData.css'

export interface BreakdownPanelProps {
  readonly breakdown: Certain<SensitiveDataBreakdownResponse>
  readonly groupBy: MetricDimension
  readonly onGroupByChange: (dimension: MetricDimension) => void
  readonly activeFilterCount: number
}

export function BreakdownPanel({
  breakdown,
  groupBy,
  onGroupByChange,
  activeFilterCount,
}: Readonly<BreakdownPanelProps>) {
  const buckets: DimensionBucket[] = isKnown(breakdown) ? breakdown.value.buckets : []
  const maxFindings = Math.max(0, ...buckets.map((b) => b.finding_count))

  return (
    <section className="sd-panel" data-testid="sd-breakdown">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Breakdown</h2>
        <label className="sd-field">
          Group by
          <select
            data-testid="sd-breakdown-group-by"
            value={groupBy}
            onChange={(event) => onGroupByChange(event.target.value as MetricDimension)}
          >
            {GROUP_BY_DIMENSIONS.map((dimension) => (
              <option key={dimension} value={dimension}>
                {dimensionLabel(dimension)}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="sd-panel__note">
        Only the six dimensions ADR 0032 §9 permits as metric labels can be grouped by. Agent,
        destination, session and trace are unbounded as labels and belong to the event store — use
        them as filters, or rank by them under “Top offenders”.
      </p>

      {!isKnown(breakdown) ? (
        <StatusState
          state={breakdown.state}
          title="The breakdown could not be read"
          description="No grouping is shown. An empty table here would read as “no findings in any category”."
          detail={breakdown.detail}
          testId="sd-breakdown-absent"
        />
      ) : buckets.length === 0 ? (
        <StatusState
          state={null}
          title={resultTitle(readResult(0, activeFilterCount))}
          description={resultDescription(readResult(0, activeFilterCount))}
          testId="sd-breakdown-empty"
        />
      ) : (
        <div className="sd-table__scroll">
          <table className="sd-table" data-testid="sd-breakdown-table">
            <thead>
              <tr>
                <th scope="col">{dimensionLabel(breakdown.value.group_by)}</th>
                <th scope="col">Findings</th>
                <th scope="col" className="sd-bar-cell">
                  <span className="sd-sr-only">Findings, relative</span>
                </th>
                <th scope="col">Actions carrying at least one</th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((bucket) => (
                <tr key={bucket.value} data-testid={`sd-breakdown-row-${bucket.value}`}>
                  <td>{bucket.value}</td>
                  <td className="sd-num" data-testid={`sd-breakdown-findings-${bucket.value}`}>
                    {formatCount(bucket.finding_count)}{' '}
                    <span className="sd-figure__unit">
                      {measureUnitNoun('finding', bucket.finding_count)}
                    </span>
                  </td>
                  <td>
                    <span
                      className="sd-bar sd-bar--finding"
                      style={{ width: `${barPercent(bucket.finding_count, maxFindings)}%` }}
                      aria-hidden
                    />
                  </td>
                  <td className="sd-num" data-testid={`sd-breakdown-events-${bucket.value}`}>
                    {formatCount(bucket.event_count)}{' '}
                    <span className="sd-figure__unit">
                      {measureUnitNoun('event', bucket.event_count)}
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
