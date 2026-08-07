/**
 * The counters panel's truthfulness contract (AAASM-5360).
 *
 * Two properties, both of which a plausible-looking panel could break:
 *
 *  1. **No figure is rendered without its unit.** ADR 0032 §8's worked example
 *     produces `1` and `3` from one action; either alone is wrong.
 *  2. **A window whose inspection did not complete does not render as complete.**
 *
 * ## Falsification record
 *
 *  - **M-H — render the number without the noun.** Delete the
 *    `sd-figure__unit` span from `CountFigure`, leaving the value. **2 failed, 5
 *    passed (7):** `renders every figure with the unit it is counted in` and
 *    `renders the §8 worked example as six figures, never as one number`.
 *    The second is the one that matters: it is the assertion that a card
 *    labelled just "3" or just "1" fails.
 *
 *  - **M-I — treat an incomplete inspection as complete.** Override the panel's
 *    coverage with `complete: true`, so a lossy window renders the complete
 *    sentence. **1 failed, 6 passed (7):**
 *    `does not render a window with an incomplete inspection pass as a complete one`.
 *    A different mutation from M-H killing a different test — and a different
 *    test from the pure-function one M-C kills in `measures.test.ts`, so the
 *    component-level and vocabulary-level claims are proved separately rather
 *    than one being counted twice.
 */
import { render, screen, within } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { CountersPanel } from './CountersPanel'
import { MEASURE_PAIRS } from './measures'
import type { SensitiveDataCounters, SensitiveDataSummaryResponse } from './schema'
import {
  LOSSY_INSPECTION_COUNTERS,
  SCOPE,
  UNMEASURED_COUNTERS,
  WORKED_EXAMPLE_COUNTERS,
  ZERO_COUNTERS,
  ratesFor,
} from './__tests__/fixtures'

const summaryOf = (counters: SensitiveDataCounters): SensitiveDataSummaryResponse => ({
  scope: SCOPE,
  counters,
  rates: ratesFor(counters),
  by_category: [],
})

const renderPanel = (counters: SensitiveDataCounters) =>
  render(<CountersPanel summary={known(summaryOf(counters))} />)

describe('CountersPanel', () => {
  it('renders every figure with the unit it is counted in', () => {
    renderPanel(UNMEASURED_COUNTERS)
    // Sweep every rendered figure rather than the four this panel happens to
    // pair: a figure added later without a noun fails here too.
    const figures = screen.getAllByTestId(/^sd-figure-/)
    expect(figures.length).toBeGreaterThan(0)
    for (const figure of figures) {
      const unit = figure.getAttribute('data-unit')
      expect(['event', 'finding']).toContain(unit)
      // "12 actions", never "12".
      expect(figure.textContent?.trim()).toMatch(/^[\d,]+ (actions?|findings?)$/)
    }
  })

  it('renders the §8 worked example as six figures, never as one number', () => {
    // One action, three findings, two rewritten before it was refused. Both
    // numbers are true; a card showing either alone is the defect.
    renderPanel(WORKED_EXAMPLE_COUNTERS)

    expect(screen.getByTestId('sd-figure-event_count')).toHaveTextContent('1 action')
    expect(screen.getByTestId('sd-figure-finding_count')).toHaveTextContent('3 findings')
    expect(screen.getByTestId('sd-figure-blocked_event_count')).toHaveTextContent('1 action')
    expect(screen.getByTestId('sd-figure-blocked_finding_count')).toHaveTextContent('3 findings')
    expect(screen.getByTestId('sd-figure-redacted_event_count')).toHaveTextContent('0 actions')
    expect(screen.getByTestId('sd-figure-redacted_finding_count')).toHaveTextContent('2 findings')

    // The two halves of a pair never read the same, in either direction.
    expect(screen.getByTestId('sd-figure-event_count').textContent).not.toBe(
      screen.getByTestId('sd-figure-finding_count').textContent,
    )
    expect(screen.getByTestId('sd-figure-blocked_event_count').textContent).not.toBe(
      screen.getByTestId('sd-figure-blocked_finding_count').textContent,
    )
  })

  it('keeps each action figure beside the finding figure that measures the same population', () => {
    renderPanel(WORKED_EXAMPLE_COUNTERS)
    for (const [eventId, findingId] of MEASURE_PAIRS) {
      const pair = within(screen.getByTestId(`sd-pair-${eventId}`))
      expect(pair.getByTestId(`sd-figure-${eventId}`)).toHaveAttribute('data-unit', 'event')
      expect(pair.getByTestId(`sd-figure-${findingId}`)).toHaveAttribute('data-unit', 'finding')
    }
  })

  it('labels the redaction tally as operations performed, not as findings delivered', () => {
    // On a blocked action nothing reached the wire, however many of its findings
    // were rewritten first. A "redacted and sent" label would invent a delivery
    // claim out of a transformation count.
    renderPanel(WORKED_EXAMPLE_COUNTERS)
    const measure = screen.getByTestId('sd-measure-redacted_finding_count')
    expect(measure).toHaveTextContent('Redaction operations performed')
    expect(measure).toHaveTextContent('nothing reached the wire')
    expect(measure.textContent).not.toMatch(/delivered|transmitted successfully/i)
  })

  it('does not render a window with an incomplete inspection pass as a complete one', () => {
    const { unmount } = renderPanel(UNMEASURED_COUNTERS)
    expect(screen.getByTestId('sd-inspection-coverage')).toHaveAttribute('data-complete', 'true')
    unmount()

    renderPanel(LOSSY_INSPECTION_COUNTERS)
    const notice = screen.getByTestId('sd-inspection-coverage')
    expect(notice).toHaveAttribute('data-complete', 'false')
    expect(notice).toHaveTextContent('5 of 12')
    expect(notice).toHaveTextContent('did not run their detection pass to completion')
    expect(notice).toHaveTextContent('nothing established what they carried')
    // Announced, because the figures above it are counting those actions as
    // though they had been inspected.
    expect(notice).toHaveAttribute('role', 'status')
    expect(notice.className).toContain('sd-coverage--incomplete')
  })

  it('bounds the complete-pass claim to the actions the projection holds', () => {
    // No response field reports whether the window itself lost anything, so the
    // sentence must not imply the window is known complete.
    renderPanel(ZERO_COUNTERS)
    expect(screen.getByTestId('sd-inspection-coverage')).toHaveTextContent(
      'no inspection coverage to report',
    )

    render(<CountersPanel summary={known(summaryOf(UNMEASURED_COUNTERS))} />)
    expect(screen.getAllByTestId('sd-inspection-coverage')[1]).toHaveTextContent(
      'no field on this response reports whether the window itself lost any',
    )
  })

  it('shows no figure at all when the counters could not be read', () => {
    render(<CountersPanel summary={absent('unknown', 'counters: Required')} />)
    expect(screen.queryByTestId(/^sd-figure-/)).toBeNull()
    expect(screen.getByTestId('sd-counters-absent')).toHaveTextContent(
      'The counters could not be read',
    )
    expect(screen.getByTestId('sd-counters-absent')).toHaveTextContent('counters: Required')
  })
})
