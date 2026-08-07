/**
 * Timestamp and width rendering (AAASM-5360).
 *
 * ## Falsification record
 *
 *  - **M-J — feed nanoseconds straight to `Date`.** Drop the `/ NS_PER_MS`
 *    division in `formatInstantNs`. **2 failed, 5 passed (7):**
 *    `renders an epoch-nanosecond instant as a UTC minute` and
 *    `renders a window as two absolute UTC instants`. Worth testing precisely
 *    because it does *not* throw — `new Date(1.76e18)` is a real date, in the
 *    year 55,760,000, and it renders without complaining.
 *  - **M-K — draw a bar for a zero.** Change `barPercent`'s guard from
 *    `value <= 0` to `value < 0`, so a zero falls through to the `Math.max(1, …)`
 *    floor. **1 failed, 6 passed (7):**
 *    `draws no bar at all for a zero, and a visible one for a small non-zero`.
 *    Drawing a bar where nothing happened is this Epic's whole category of
 *    defect, in one pixel.
 *
 * The `.482`/`.481` millisecond assertion was not written from theory: the first
 * draft used `Math.floor` and produced `.481`, because 1.76e18 is past
 * `Number.MAX_SAFE_INTEGER` and the JSON number is not the integer the server
 * sent. The test is the record of that.
 */
import { describe, it, expect } from 'vitest'
import {
  barPercent,
  formatDuration,
  formatInstantNs,
  formatInstantNsPrecise,
  formatWindow,
} from './format'

describe('formatInstantNs', () => {
  it('renders an epoch-nanosecond instant as a UTC minute', () => {
    // 2025-10-09T08:53:20Z. Chosen so a millisecond/nanosecond mix-up lands in
    // a visibly different era rather than a nearby second — see M-J below.
    expect(formatInstantNs(1_760_000_000_000_000_000)).toBe('2025-10-09 08:53 UTC')
  })

  it('renders a single event to the millisecond, because ordering matters there', () => {
    expect(formatInstantNsPrecise(1_760_000_000_482_000_000)).toBe(
      '2025-10-09 08:53:20.482 UTC',
    )
  })

  it('says so rather than rendering a plausible date when the number is not a time', () => {
    expect(formatInstantNs(Number.NaN)).toBe('unknown time')
  })
})

describe('formatWindow', () => {
  it('renders a window as two absolute UTC instants', () => {
    expect(formatWindow(1_760_000_000_000_000_000, 1_760_604_800_000_000_000)).toBe(
      '2025-10-09 08:53 UTC → 2025-10-16 08:53 UTC',
    )
  })
})

describe('formatDuration', () => {
  it('names each bucket width in its largest whole unit', () => {
    expect(formatDuration(86_400)).toBe('1 day')
    expect(formatDuration(604_800)).toBe('7 days')
    expect(formatDuration(3_600)).toBe('1 hour')
    expect(formatDuration(21_600)).toBe('6 hours')
    expect(formatDuration(90)).toBe('90 seconds')
  })
})

describe('barPercent', () => {
  it('draws no bar at all for a zero, and a visible one for a small non-zero', () => {
    // A minimum-width bar for a zero would draw something where nothing
    // happened, which on this surface is the whole category of defect.
    expect(barPercent(0, 100)).toBe(0)
    expect(barPercent(1, 1_000)).toBe(1)
    expect(barPercent(50, 100)).toBe(50)
    expect(barPercent(100, 100)).toBe(100)
  })

  it('draws nothing when there is no maximum to scale against', () => {
    expect(barPercent(5, 0)).toBe(0)
  })
})
