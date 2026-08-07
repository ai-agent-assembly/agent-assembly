/**
 * The prevention panel's truthfulness contract (AAASM-5360 / AAASM-5685).
 *
 * This is the most load-bearing test file in the feature. `prevention_rate` is
 * structurally `0` on every build shipping today — nothing writes
 * `TransmissionEvidence::NotForwarded`, so the four §8 prevention conditions can
 * never all hold — and rendering that as "0% prevented" says the opposite of
 * what is true.
 *
 * ## Falsification record
 *
 *  - **M-F — render the rate alone.** Replace the panel's body with just
 *    `{formatRate(summary.value.rates.prevention_rate)} prevented`, dropping the
 *    badge, the qualifier, the cause and the announcement — i.e. exactly the KPI
 *    card this panel exists instead of. **6 failed, 1 passed (7).** The six:
 *    `renders a structural zero with its unmeasured share, badge, qualifier and cause`,
 *    `renders a measured zero completely differently from a structural zero`,
 *    `announces the reason there is no measurement, never an all-clear`,
 *    `renders a partly-measured window as neither of the two extremes`,
 *    `renders a real measured prevention rate as a measurement`, and
 *    `says there was nothing to measure over an empty window rather than showing 0%`.
 *    The survivor is `does not render a prevention figure at all when the
 *    summary could not be read`, which exercises the absent branch the mutation
 *    did not touch — so it is not evidence about this one.
 *
 *  - **M-G — drop only the qualifier**, keeping the headline, the badge, the
 *    cause and the announcement, to check the tests are not merely detecting the
 *    badge. **5 failed, 2 passed (7):** the same six as M-F minus
 *    `announces the reason there is no measurement, never an all-clear`, which
 *    survives because the composed announcement is built independently of the
 *    rendered paragraph. That survivor is informative rather than a gap: it says
 *    the visual and the spoken contract are separately enforced, so a build can
 *    lose one without losing the other quietly.
 */
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { PreventionPanel } from './PreventionPanel'
import type { SensitiveDataSummaryResponse } from './schema'
import {
  MEASURED_PREVENTION_COUNTERS,
  MEASURED_ZERO_COUNTERS,
  SCOPE,
  UNMEASURED_COUNTERS,
  ratesFor,
} from './__tests__/fixtures'
import type { SensitiveDataCounters } from './schema'

const summaryOf = (counters: SensitiveDataCounters): SensitiveDataSummaryResponse => ({
  scope: SCOPE,
  counters,
  rates: ratesFor(counters),
  by_category: [],
})

const renderPanel = (counters: SensitiveDataCounters) =>
  render(<PreventionPanel summary={known(summaryOf(counters))} />)

describe('PreventionPanel', () => {
  it('renders a structural zero with its unmeasured share, badge, qualifier and cause', () => {
    // The state every build is in today: twelve inspected actions, none of which
    // recorded what happened to the bytes.
    renderPanel(UNMEASURED_COUNTERS)
    const panel = screen.getByTestId('sd-prevention')

    expect(panel).toHaveAttribute('data-prevention-reading', 'unmeasured')
    // The rate never appears without the unmeasured share beside it.
    expect(screen.getByTestId('sd-prevention-headline')).toHaveTextContent(
      '0% prevented — 100% unmeasured',
    )
    expect(screen.getByTestId('sd-prevention-status')).toHaveTextContent('Unmeasured')
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent(
      'This figure is an absent measurement, not a measured absence of prevention.',
    )
    expect(screen.getByTestId('sd-prevention-cause')).toHaveTextContent('AAASM-5685')
    // And the bare, false reading is nowhere on the panel.
    expect(panel.textContent).not.toMatch(/0% prevented(?! —)/)
  })

  it('renders a measured zero completely differently from a structural zero', () => {
    // Same `prevention_rate` — `0` — for both windows. Everything the operator
    // sees has to differ, or the two conclusions collapse into one.
    const { unmount } = renderPanel(UNMEASURED_COUNTERS)
    const structuralText = screen.getByTestId('sd-prevention').textContent
    unmount()

    renderPanel(MEASURED_ZERO_COUNTERS)
    const panel = screen.getByTestId('sd-prevention')

    expect(panel).toHaveAttribute('data-prevention-reading', 'measured')
    expect(screen.getByTestId('sd-prevention-headline')).toHaveTextContent(
      '0% prevented — 0% unmeasured',
    )
    expect(screen.getByTestId('sd-prevention-status')).toHaveTextContent('Measured')
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent(
      'this figure is a measurement',
    )
    // No AAASM-5685 note: prevention *was* measured here, and it was zero.
    expect(screen.queryByTestId('sd-prevention-cause')).toBeNull()

    expect(panel.textContent).not.toBe(structuralText)
  })

  it('announces the reason there is no measurement, never an all-clear', () => {
    renderPanel(UNMEASURED_COUNTERS)
    const spoken = screen.getByTestId('sd-prevention-announcement').textContent ?? ''

    expect(spoken).toContain('Prevention: Unmeasured.')
    expect(spoken).toContain('0% prevented — 100% unmeasured')
    expect(spoken).toContain('absent measurement, not a measured absence')
    expect(spoken).toContain('AAASM-5685')

    // The live region is polite, not assertive: an unmeasured figure is a
    // standing condition of this build, not an incident to interrupt for.
    expect(screen.getByTestId('sd-prevention')).toHaveAttribute('aria-live', 'polite')
  })

  it('renders a partly-measured window as neither of the two extremes', () => {
    renderPanel({ ...UNMEASURED_COUNTERS, unmeasured_transmission_event_count: 7 })
    expect(screen.getByTestId('sd-prevention')).toHaveAttribute(
      'data-prevention-reading',
      'partly-measured',
    )
    expect(screen.getByTestId('sd-prevention-status')).toHaveTextContent('Partly measured')
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent('7 of 12')
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent(
      'understates what may have been prevented',
    )
  })

  it('renders a real measured prevention rate as a measurement', () => {
    renderPanel(MEASURED_PREVENTION_COUNTERS)
    expect(screen.getByTestId('sd-prevention-headline')).toHaveTextContent(
      '25% prevented — 0% unmeasured',
    )
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent(
      '3 actions met all four ADR 0032 §8 prevention conditions',
    )
  })

  it('says there was nothing to measure over an empty window rather than showing 0%', () => {
    renderPanel({
      ...UNMEASURED_COUNTERS,
      event_count: 0,
      finding_count: 0,
      blocked_event_count: 0,
      blocked_finding_count: 0,
      redacted_event_count: 0,
      redacted_finding_count: 0,
      unmeasured_transmission_event_count: 0,
    })
    expect(screen.getByTestId('sd-prevention')).toHaveAttribute(
      'data-prevention-reading',
      'nothing-inspected',
    )
    expect(screen.getByTestId('sd-prevention-headline')).toHaveTextContent('Not measured')
    expect(screen.getByTestId('sd-prevention-qualifier')).toHaveTextContent(
      'This is not a clean bill of health for the window',
    )
  })

  it('does not render a prevention figure at all when the summary could not be read', () => {
    render(<PreventionPanel summary={absent('unavailable', 'the gateway did not answer')} />)
    expect(screen.queryByTestId('sd-prevention-headline')).toBeNull()
    expect(screen.getByTestId('sd-prevention-absent')).toHaveTextContent(
      'Prevention could not be read',
    )
    // A zero here would be indistinguishable from a measured one, which is the
    // whole complaint — so there is no zero to find.
    expect(screen.getByTestId('sd-prevention').textContent).not.toContain('0%')
  })
})
