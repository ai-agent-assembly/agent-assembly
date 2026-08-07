/**
 * The sensitive-data measure vocabulary (AAASM-5360).
 *
 * ## Falsification record
 *
 * Every assertion here was watched failing against a deliberately broken build
 * before it was trusted. Recorded with the numbers, because "a test exists" and
 * "a test would catch it" are different claims:
 *
 *  - **M-A — collapse the units.** Change the `'finding'` entry of `UNIT_NOUNS`
 *    to `{ one: 'action', many: 'actions' }`, so a finding count renders under
 *    the same noun an action count does. **3 failed, 22 passed (25).** The three:
 *    `gives every counter a unit noun that is distinct across the two units`,
 *    `renders the §8 worked example as six figures in two different units`, and
 *    `describes the redaction counter as operations performed, not as findings sent`.
 *    Restoring the entry returns all three to green.
 *
 *  - **M-B — read prevention without the unmeasured counter.** Disable both
 *    `unmeasuredCount` branches of `readPrevention`, so every non-empty window
 *    reports `measured`. **5 failed, 20 passed (25).** The five:
 *    `classifies a window with no transmission evidence as unmeasured`,
 *    `classifies a mixed window as partly measured`,
 *    `never produces the same headline, badge and qualifier for a structural zero as for a measured zero`,
 *    `names AAASM-5685 as the cause only when prevention is unmeasurable`, and
 *    `announces the reason there is no measurement rather than an all-clear`.
 *    This mutation is the exact shape of the AAASM-5685 defect, and it kills a
 *    different set of tests from M-A — no test is counted as evidence twice.
 *
 *  - **M-C — treat an incomplete inspection as complete.** Change
 *    `readInspectionCoverage` to return `complete: true` unconditionally.
 *    **1 failed, 24 passed (25):**
 *    `does not report a window with an incomplete inspection pass as complete`.
 *    That single failure is the whole of the evidence for requirement 3 at this
 *    layer; the component-level proof is a separate test in
 *    `CountersPanel.test.tsx` killed by a separate mutation.
 */
import { describe, it, expect } from 'vitest'
import {
  MEASURE_IDS,
  MEASURE_PAIRS,
  countMeasure,
  countMeasureText,
  countMeasures,
  formatRate,
  inspectionCoverageSentence,
  measureUnitNoun,
  pageCoverageSentence,
  preventionAnnouncement,
  preventionCause,
  preventionHeadline,
  preventionQualifier,
  preventionStatusLabel,
  readInspectionCoverage,
  readPageCoverage,
  readPrevention,
  readResult,
  resultDescription,
  resultTitle,
} from './measures'
import {
  LOSSY_INSPECTION_COUNTERS,
  MEASURED_PREVENTION_COUNTERS,
  MEASURED_ZERO_COUNTERS,
  UNMEASURED_COUNTERS,
  WORKED_EXAMPLE_COUNTERS,
  ZERO_COUNTERS,
  ratesFor,
} from './__tests__/fixtures'

describe('units', () => {
  it('gives every counter a unit noun that is distinct across the two units', () => {
    // The property that makes "3" under an "actions" heading impossible: the two
    // units never share a word, in either grammatical number.
    const eventWords = new Set([measureUnitNoun('event', 1), measureUnitNoun('event', 7)])
    const findingWords = new Set([measureUnitNoun('finding', 1), measureUnitNoun('finding', 7)])
    for (const word of eventWords) {
      expect(findingWords.has(word), `"${word}" is used for both units`).toBe(false)
    }
    // ...and every counter maps to one of the two, so none can be rendered bare.
    for (const id of MEASURE_IDS) {
      const measure = countMeasure(id, ZERO_COUNTERS)
      expect(['event', 'finding']).toContain(measure.unit)
      expect(countMeasureText(measure)).toMatch(/^\d[\d,]* [a-z]+$/)
    }
  })

  it('covers every counter the API sends, so none can be rendered without a definition', () => {
    expect([...MEASURE_IDS].sort()).toEqual(Object.keys(ZERO_COUNTERS).sort())
  })

  it('renders the §8 worked example as six figures in two different units', () => {
    // One action, three findings, two rewritten before the action was refused.
    // Every one of these six numbers is true, of a different thing.
    const measures = new Map(
      countMeasures(WORKED_EXAMPLE_COUNTERS).map((m) => [m.id, countMeasureText(m)]),
    )
    expect(measures.get('event_count')).toBe('1 action')
    expect(measures.get('finding_count')).toBe('3 findings')
    expect(measures.get('blocked_event_count')).toBe('1 action')
    expect(measures.get('blocked_finding_count')).toBe('3 findings')
    expect(measures.get('redacted_event_count')).toBe('0 actions')
    expect(measures.get('redacted_finding_count')).toBe('2 findings')
    // And the two halves of the headline pair are never the same string, which
    // is what a card labelled just "3" or just "1" would have made them.
    expect(measures.get('event_count')).not.toBe(measures.get('finding_count'))
  })

  it('pairs each action counter with the finding counter that measures the same thing', () => {
    for (const [eventId, findingId] of MEASURE_PAIRS) {
      expect(countMeasure(eventId, ZERO_COUNTERS).unit).toBe('event')
      expect(countMeasure(findingId, ZERO_COUNTERS).unit).toBe('finding')
    }
  })

  it('describes the redaction counter as operations performed, not as findings sent', () => {
    // `redacted_finding_count` counts transformations, including on actions that
    // were then blocked, where nothing reached the wire. Labelling it
    // "findings redacted and sent" would invent a delivery claim from a
    // transformation tally.
    const redacted = countMeasure('redacted_finding_count', WORKED_EXAMPLE_COUNTERS)
    expect(redacted.label).toBe('Redaction operations performed')
    expect(redacted.unit).toBe('finding')
    expect(redacted.description).toContain('nothing reached the wire')
    expect(countMeasureText(redacted)).toBe('2 findings')
  })
})

describe('formatRate', () => {
  it('renders an absent rate as the no-data glyph, never as 0%', () => {
    expect(formatRate(null)).toBe('—')
    expect(formatRate(undefined)).toBe('—')
  })

  it('renders a measured zero as 0%, because that one is a measurement', () => {
    expect(formatRate(0)).toBe('0%')
  })

  it('keeps a small non-zero share visible rather than rounding it to none', () => {
    expect(formatRate(0.004)).toBe('0.4%')
    expect(formatRate(1)).toBe('100%')
  })
})

describe('readPrevention', () => {
  it('classifies an empty window as nothing to measure', () => {
    expect(readPrevention(ZERO_COUNTERS, ratesFor(ZERO_COUNTERS)).kind).toBe('nothing-inspected')
  })

  it('classifies a window with no transmission evidence as unmeasured', () => {
    // Every build shipping today is in this state: the gateway producer writes
    // `TransmissionEvidence::NotRecorded` unconditionally (AAASM-5685).
    const reading = readPrevention(UNMEASURED_COUNTERS, ratesFor(UNMEASURED_COUNTERS))
    expect(reading.kind).toBe('unmeasured')
    expect(preventionStatusLabel(reading)).toBe('Unmeasured')
  })

  it('classifies a fully-evidenced window as measured even when nothing was prevented', () => {
    const reading = readPrevention(MEASURED_ZERO_COUNTERS, ratesFor(MEASURED_ZERO_COUNTERS))
    expect(reading.kind).toBe('measured')
    expect(preventionStatusLabel(reading)).toBe('Measured')
  })

  it('classifies a mixed window as partly measured', () => {
    const mixed = { ...UNMEASURED_COUNTERS, unmeasured_transmission_event_count: 7 }
    const reading = readPrevention(mixed, ratesFor(mixed))
    expect(reading.kind).toBe('partly-measured')
    expect(preventionQualifier(reading)).toContain('7 of 12')
    expect(preventionQualifier(reading)).toContain('remaining 5')
  })
})

describe('the structural zero versus the measured zero', () => {
  const structural = readPrevention(UNMEASURED_COUNTERS, ratesFor(UNMEASURED_COUNTERS))
  const measured = readPrevention(MEASURED_ZERO_COUNTERS, ratesFor(MEASURED_ZERO_COUNTERS))

  it('produces the same raw prevention rate for both, which is why the rate alone is not enough', () => {
    // Both windows have `prevention_rate = 0`. Everything below is what stops
    // the two from rendering identically. If this assertion ever fails, the
    // fixtures have drifted and the rest of this block proves nothing.
    expect(formatRate(ratesFor(UNMEASURED_COUNTERS).prevention_rate)).toBe('0%')
    expect(formatRate(ratesFor(MEASURED_ZERO_COUNTERS).prevention_rate)).toBe('0%')
  })

  it('never produces the same headline, badge and qualifier for a structural zero as for a measured zero', () => {
    expect(preventionHeadline(structural)).toBe('0% prevented — 100% unmeasured')
    expect(preventionHeadline(measured)).toBe('0% prevented — 0% unmeasured')
    expect(preventionHeadline(structural)).not.toBe(preventionHeadline(measured))

    expect(preventionStatusLabel(structural)).toBe('Unmeasured')
    expect(preventionStatusLabel(measured)).toBe('Measured')

    expect(preventionQualifier(structural)).toContain(
      'This figure is an absent measurement, not a measured absence of prevention.',
    )
    expect(preventionQualifier(measured)).toContain('this figure is a measurement')
    expect(preventionQualifier(structural)).not.toBe(preventionQualifier(measured))
  })

  it('never claims prevention for the structural zero, and never claims it for real prevention either without evidence', () => {
    const real = readPrevention(MEASURED_PREVENTION_COUNTERS, ratesFor(MEASURED_PREVENTION_COUNTERS))
    expect(preventionHeadline(real)).toBe('25% prevented — 0% unmeasured')
    expect(preventionQualifier(real)).toContain('3 actions met all four')
  })

  it('names AAASM-5685 as the cause only when prevention is unmeasurable', () => {
    expect(preventionCause(structural)).toContain('AAASM-5685')
    expect(preventionCause(measured)).toBeNull()
    expect(preventionCause(readPrevention(ZERO_COUNTERS, ratesFor(ZERO_COUNTERS)))).toBeNull()
  })

  it('announces the reason there is no measurement rather than an all-clear', () => {
    // The `aria-live` sentence. A screen-reader user must not be told "0%
    // prevented" and left to infer the rest from a badge they cannot see.
    const spoken = preventionAnnouncement(structural)
    expect(spoken).toContain('Unmeasured')
    expect(spoken).toContain('100% unmeasured')
    expect(spoken).toContain('absent measurement, not a measured absence')
    expect(spoken).toContain('AAASM-5685')
    expect(spoken).not.toBe(preventionAnnouncement(measured))
  })
})

describe('inspection coverage', () => {
  it('does not report a window with an incomplete inspection pass as complete', () => {
    const coverage = readInspectionCoverage(LOSSY_INSPECTION_COUNTERS)
    expect(coverage.complete).toBe(false)
    expect(coverage.incompleteCount).toBe(5)
    const sentence = inspectionCoverageSentence(coverage)
    expect(sentence).toContain('5 of 12')
    expect(sentence).toContain('did not run their detection pass to completion')
    expect(sentence).toContain('nothing established what they carried')
  })

  it('reports a complete pass as complete, and says what that does and does not cover', () => {
    const coverage = readInspectionCoverage(UNMEASURED_COUNTERS)
    expect(coverage.complete).toBe(true)
    const sentence = inspectionCoverageSentence(coverage)
    expect(sentence).toContain('ran its detection pass to completion')
    // The claim is bounded on purpose. No response field reports window loss, so
    // the sentence must not imply the window itself is known complete.
    expect(sentence).toContain('no field on this response reports whether the window itself lost any')
  })

  it('says there is no coverage to report when nothing was inspected', () => {
    expect(inspectionCoverageSentence(readInspectionCoverage(ZERO_COUNTERS))).toContain(
      'no inspection coverage to report',
    )
  })
})

describe('page coverage', () => {
  it('labels a truncated page as a page, not as the total', () => {
    const coverage = readPageCoverage(100, 940)
    expect(coverage.truncated).toBe(true)
    expect(pageCoverageSentence(coverage)).toBe(
      'Showing 100 of 940 matching actions. The rest are counted in the figures above but are not on this page — narrow the filters or shorten the window to see them.',
    )
  })

  it('says so when the page is the whole set', () => {
    expect(pageCoverageSentence(readPageCoverage(3, 3))).toBe('Showing all 3 matching actions.')
  })
})

describe('empty versus zero', () => {
  it('separates "nothing was recorded" from "nothing matched these filters"', () => {
    const nothingRecorded = readResult(0, 0)
    const nothingMatched = readResult(0, 2)
    expect(nothingRecorded.kind).toBe('nothing-recorded')
    expect(nothingMatched.kind).toBe('nothing-matched')
    expect(resultTitle(nothingRecorded)).not.toBe(resultTitle(nothingMatched))
    expect(resultTitle(nothingRecorded)).toBe('No sensitive data recorded in this window')
    expect(resultTitle(nothingMatched)).toBe('No action matched these filters')
    expect(resultDescription(nothingMatched)).toContain('Other actions may exist')
  })

  it('does not turn "none recorded" into a claim that none occurred', () => {
    expect(resultDescription(readResult(0, 0))).toContain(
      'it is not a statement that no sensitive data moved',
    )
  })

  it('reports a populated window as populated regardless of filters', () => {
    expect(readResult(12, 3)).toEqual({ kind: 'populated', eventCount: 12 })
  })
})
