/**
 * The ADR 0032 §8 counters, in pairs, with their units (AAASM-5360).
 *
 * ## Why the figures are laid out in pairs
 *
 * Every §8 counter has a partner that measures the *other* unit over the same
 * population: `event_count`/`finding_count`, `blocked_event_count`/
 * `blocked_finding_count`, and so on. Showing one of a pair alone is how a `3`
 * ends up under an "actions" heading. So the panel iterates
 * {@link MEASURE_PAIRS} and renders both members of each, each through
 * {@link CountFigure}, which cannot render a value without its unit noun.
 *
 * `redacted_finding_count` is labelled *redaction operations performed*. It
 * counts transformations the pipeline carried out — including on actions it then
 * refused, where nothing reached the wire — so any label implying delivery would
 * be a claim the counter does not support.
 *
 * ## The inspection-coverage notice
 *
 * `inspection_incomplete_event_count` says how many of these actions did not run
 * their detection pass to completion. Those actions are counted in every figure
 * above as though they had been inspected, and they were not. The notice is
 * rendered whenever that count is non-zero, in a caution tone, and the sentence
 * says what a complete pass does and does not establish: it covers the actions
 * the projection holds, and **no field on any of these responses reports whether
 * the window itself lost any**. Saying "this window is complete" would be a
 * claim with nothing behind it.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import { LabelledCount } from './CountFigure'
import {
  MEASURE_PAIRS,
  countMeasure,
  inspectionCoverageSentence,
  readInspectionCoverage,
} from './measures'
import type { SensitiveDataSummaryResponse } from './schema'
import './sensitiveData.css'

export interface CountersPanelProps {
  readonly summary: Certain<SensitiveDataSummaryResponse>
}

export function CountersPanel({ summary }: Readonly<CountersPanelProps>) {
  if (!isKnown(summary)) {
    return (
      <section className="sd-panel" data-testid="sd-counters">
        <StatusState
          state={summary.state}
          title="The counters could not be read"
          description="No figure is shown. A zeroed dictionary would be indistinguishable from a quiet window."
          detail={summary.detail}
          testId="sd-counters-absent"
        />
      </section>
    )
  }

  const { counters } = summary.value
  const coverage = readInspectionCoverage(counters)

  return (
    <section className="sd-panel" data-testid="sd-counters">
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">What was seen, in both units</h2>
      </div>
      <p className="sd-panel__note">
        Actions and findings are different counts of different things. One action can carry many
        findings, so the two are never interchangeable and neither is shown without its unit.
      </p>

      <div className="sd-grid">
        {MEASURE_PAIRS.map(([eventId, findingId]) => (
          <div className="sd-measure-pair" key={eventId} data-testid={`sd-pair-${eventId}`}>
            <LabelledCount measure={countMeasure(eventId, counters)} />
            <hr className="sd-measure-pair__rule" />
            <LabelledCount measure={countMeasure(findingId, counters)} />
          </div>
        ))}
      </div>

      <p
        className={
          coverage.complete
            ? 'sd-coverage sd-coverage--spaced'
            : 'sd-coverage sd-coverage--spaced sd-coverage--incomplete'
        }
        data-testid="sd-inspection-coverage"
        data-complete={coverage.complete ? 'true' : 'false'}
        role={coverage.complete ? undefined : 'status'}
      >
        {inspectionCoverageSentence(coverage)}
      </p>
    </section>
  )
}
