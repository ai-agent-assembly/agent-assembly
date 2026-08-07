/**
 * The one way a sensitive-data count reaches the screen (AAASM-5360).
 *
 * It takes a {@link CountMeasure}, never a bare number, and it always renders
 * the unit noun beside the value. There is no prop that suppresses the noun and
 * no overload that accepts a number — which is what makes ADR 0032's
 * event/finding distinction a property of the component tree rather than of
 * whoever wrote the last panel.
 *
 * The canonical failure this prevents: an action carrying three findings that
 * was blocked produces `1` and `3`, both true. A card showing either alone is
 * wrong whichever one it is.
 */
import { formatCount, measureUnitNoun, type CountMeasure } from './measures'
import './sensitiveData.css'

export interface CountFigureProps {
  readonly measure: CountMeasure
  /** Render at body size, for use inside a sentence or a table cell. */
  readonly inline?: boolean
  readonly testId?: string
}

export function CountFigure({ measure, inline = false, testId }: Readonly<CountFigureProps>) {
  return (
    <span
      className={inline ? 'sd-figure sd-figure--inline' : 'sd-figure'}
      data-testid={testId ?? `sd-figure-${measure.id}`}
      data-unit={measure.unit}
    >
      <span className="sd-figure__value">{formatCount(measure.value)}</span>{' '}
      <span className="sd-figure__unit">{measureUnitNoun(measure.unit, measure.value)}</span>
    </span>
  )
}

export interface LabelledCountProps {
  readonly measure: CountMeasure
  /** Show the measure's description beneath the label. */
  readonly showDescription?: boolean
}

/** A figure with the name of what it measures and, optionally, why. */
export function LabelledCount({ measure, showDescription = true }: Readonly<LabelledCountProps>) {
  return (
    <div className="sd-measure" data-testid={`sd-measure-${measure.id}`}>
      <span className="sd-measure__label">{measure.label}</span>
      <CountFigure measure={measure} />
      {showDescription && <span className="sd-measure__description">{measure.description}</span>}
    </div>
  )
}
