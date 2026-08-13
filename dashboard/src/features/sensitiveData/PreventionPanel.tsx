/**
 * The prevention figure, and how much of it was measurable (AAASM-5360).
 *
 * ## Why this panel exists instead of a KPI card
 *
 * `prevention_rate` is structurally `0` on every build shipping today: nothing
 * writes `TransmissionEvidence::NotForwarded`, so ADR 0032 §8's four prevention
 * conditions can never all hold (AAASM-5685). A card reading
 * **"Prevention rate: 0%"** would therefore be a false governance signal — it
 * says *we prevented nothing*, when the truth is *nothing was in a position to
 * measure whether we prevented anything*. Those are opposite conclusions about
 * the product, and they must never render identically.
 *
 * So the rate is never rendered alone. Four things go out together, and all four
 * come from `measures.ts` so a second surface cannot word them differently:
 *
 *  1. the **headline**, which always carries the unmeasured share beside the
 *     prevented share (`0% prevented — 100% unmeasured`);
 *  2. the **badge**, naming the epistemic state in one word, because an operator
 *     skimming a dashboard reads badges before percentages;
 *  3. the **qualifier**, which says what the number is evidence of;
 *  4. the **cause**, when there is one, naming AAASM-5685 so nobody concludes
 *     the product is failing to prevent things.
 *
 * `PreventionPanel.test.tsx` fails if the qualifier or badge is dropped. That is
 * deliberate and is the most load-bearing test in this feature.
 *
 * ## Accessibility
 *
 * The whole panel is a polite live region, and the visual composition is
 * `aria-hidden` in favour of one composed sentence
 * ({@link preventionAnnouncement}). A screen-reader user hears either a measured
 * number or the reason there is not one — never an unmeasured all-clear. This is
 * the AAASM-5112 rule, applied before the defect can occur rather than after.
 */
import { isKnown, type Certain } from '../../lib/truthfulness'
import { StatusState } from '../../components/truthfulness'
import {
  preventionAnnouncement,
  preventionCause,
  preventionHeadline,
  preventionQualifier,
  preventionStatusLabel,
  readPrevention,
} from './measures'
import type { SensitiveDataSummaryResponse } from './schema'
import './sensitiveData.css'

export interface PreventionPanelProps {
  readonly summary: Certain<SensitiveDataSummaryResponse>
}

export function PreventionPanel({ summary }: Readonly<PreventionPanelProps>) {
  if (!isKnown(summary)) {
    return (
      <section className="sd-panel" data-testid="sd-prevention">
        <StatusState
          state={summary.state}
          title="Prevention could not be read"
          description="No prevention figure is shown, because none was obtained. A zero here would be indistinguishable from a measured one."
          detail={summary.detail}
          testId="sd-prevention-absent"
        />
      </section>
    )
  }

  const reading = readPrevention(summary.value.counters, summary.value.rates)
  const cause = preventionCause(reading)

  return (
    <section
      className="sd-panel sd-prevention"
      data-testid="sd-prevention"
      data-prevention-reading={reading.kind}
      role="status"
      aria-live="polite"
    >
      <div className="sd-panel__head">
        <h2 className="sd-panel__title">Prevention</h2>
      </div>
      <div aria-hidden>
        <div className="sd-prevention__row">
          <span className="sd-prevention__headline" data-testid="sd-prevention-headline">
            {preventionHeadline(reading)}
          </span>
          <span
            className={`sd-badge sd-badge--${reading.kind}`}
            data-testid="sd-prevention-status"
          >
            {preventionStatusLabel(reading)}
          </span>
        </div>
        <p className="sd-prevention__qualifier" data-testid="sd-prevention-qualifier">
          {preventionQualifier(reading)}
        </p>
        {cause !== null && (
          <p className="sd-prevention__cause" data-testid="sd-prevention-cause">
            {cause}
          </p>
        )}
      </div>
      <span className="sd-sr-only" data-testid="sd-prevention-announcement">
        {preventionAnnouncement(reading)}
      </span>
    </section>
  )
}
