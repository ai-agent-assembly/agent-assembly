/**
 * The regression guard for AAASM-5112's three fabricated literals, kept honest
 * against AAASM-5174 having since shipped (AAASM-5347).
 *
 * Reading the constants is not the point; the point is that they are absences,
 * that none of the removed strings can come back through them, and — new here —
 * that none of them still justifies itself with the expired premise that no
 * scrub route exists.
 */
import { describe, it, expect } from 'vitest'
import * as postureModule from '../posture'
import {
  LEAK_POSTURE,
  SCRUBBING_RUNTIME_STATE,
  SCRUB_COVERAGE,
  SCRUB_POLICY,
} from '../posture'
import { isKnown, type Certain } from '../../../lib/truthfulness'

const ALL: ReadonlyArray<readonly [string, Certain<unknown>]> = [
  ['LEAK_POSTURE', LEAK_POSTURE],
  ['SCRUB_COVERAGE', SCRUB_COVERAGE],
  ['SCRUB_POLICY', SCRUB_POLICY],
  ['SCRUBBING_RUNTIME_STATE', SCRUBBING_RUNTIME_STATE],
]

describe('scrub posture constants', () => {
  it.each(ALL)('%s is an absence, never a value', (_name, value) => {
    expect(isKnown(value)).toBe(false)
  })

  it.each(ALL)('%s is not-supported — waiting will not produce it', (_name, value) => {
    if (!isKnown(value)) expect(value.state).toBe('not-supported')
  })

  it.each(ALL)('%s carries an operator-facing reason', (_name, value) => {
    if (!isKnown(value)) {
      expect(value.detail).toBeDefined()
      expect(value.detail?.length ?? 0).toBeGreaterThan(20)
    }
  })

  it.each(ALL)('%s no longer claims that no scrub route exists', (_name, value) => {
    // The reason strings used to end "(AAASM-5174)", shorthand for "the backend
    // has no such endpoint". Three of them now do. A reason that still points at
    // that ticket is a reason that has stopped being true.
    if (!isKnown(value)) {
      expect(value.detail).not.toContain('AAASM-5174')
      expect(value.detail).not.toMatch(/no (?:scrub|DLP) endpoint/i)
    }
  })

  it.each(ALL)('%s carries no demo sample that could be mistaken for a fact', (_name, value) => {
    if (!isKnown(value)) expect(value.sample).toBeUndefined()
  })

  it('no longer declares per-detector counts unsupported, now that they are served', () => {
    // `DETECTOR_HITS_24H` was the module's fifth constant. `/scrub/pattern-counts`
    // sources that column, so keeping a hard-coded "not supported" beside a live
    // fetch would be the page refusing to report what it has just been told.
    expect(postureModule).not.toHaveProperty('DETECTOR_HITS_24H')
  })

  it('carries none of the literals the page used to assert', () => {
    // Serialising the whole module is the cheapest way to make a re-introduced
    // literal — anywhere in it — fail rather than merely go unnoticed.
    const serialised = JSON.stringify(ALL)
    for (const literal of [
      '0 leaks',
      'P-100',
      'default-allow with scrub',
      'http egress',
      'gmail',
      'slack',
    ]) {
      expect(serialised).not.toContain(literal)
    }
  })
})
