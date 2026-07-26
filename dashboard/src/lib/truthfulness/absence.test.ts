import {
  NO_DATA,
  TRUTH_STATES,
  TRUTH_STATE_META,
  absent,
  certain,
  certainText,
  demo,
  isAbsent,
  isKnown,
  known,
  mapCertain,
  propagateAbsence,
  type TruthState,
} from './absence'

describe('truthfulness vocabulary', () => {
  it('covers every state with distinct, non-reassuring metadata', () => {
    expect(TRUTH_STATES).toHaveLength(6)
    const labels = TRUTH_STATES.map((state) => TRUTH_STATE_META[state].label)
    expect(new Set(labels).size).toBe(TRUTH_STATES.length)

    for (const state of TRUTH_STATES) {
      const meta = TRUTH_STATE_META[state]
      // Each state must be independently announceable — a screen reader that
      // hears only the announcement must still know nothing was measured.
      expect(meta.announcement.length).toBeGreaterThan(meta.label.length)
      expect(['neutral', 'caution', 'fault']).toContain(meta.tone)
    }
  })

  it('reserves the fault tone for a failed request', () => {
    const faults = TRUTH_STATES.filter((s) => TRUTH_STATE_META[s].tone === 'fault')
    expect(faults).toEqual(['unavailable'])
  })
})

describe('known / absent / demo', () => {
  it('narrows a known value', () => {
    const value = known(42)
    expect(isKnown(value)).toBe(true)
    expect(isAbsent(value)).toBe(false)
    if (isKnown(value)) expect(value.value).toBe(42)
  })

  it('carries the reason and detail on an absence', () => {
    const value = absent<number>('unavailable', 'HTTP 503')
    expect(isKnown(value)).toBe(false)
    if (isAbsent(value)) {
      expect(value.state).toBe('unavailable')
      expect(value.detail).toBe('HTTP 503')
    }
  })

  it('keeps demo data off the known side of the union', () => {
    const value = demo(99)
    // The sample is renderable, but `isKnown` still rejects it, so no aggregate
    // can total demo rows into a production figure.
    expect(isKnown(value)).toBe(false)
    if (isAbsent(value)) {
      expect(value.state).toBe('demo')
      expect(value.sample).toBe(99)
    }
  })
})

describe('certain()', () => {
  it.each([
    ['null', null],
    ['undefined', undefined],
    ['empty string', ''],
  ])('treats %s as missing rather than as a value', (_label, input) => {
    const value = certain(input as string | null | undefined, 'unconfigured')
    expect(isKnown(value)).toBe(false)
    if (isAbsent(value)) expect(value.state).toBe('unconfigured')
  })

  it.each([
    ['zero', 0],
    ['false', false],
    ['empty array', []],
  ])('keeps %s as a real value', (_label, input) => {
    // A measured zero is a fact; only an *absent* zero is the bug.
    expect(isKnown(certain(input, 'unknown'))).toBe(true)
  })
})

describe('mapCertain / propagateAbsence', () => {
  it('transforms a known value', () => {
    const mapped = mapCertain(known(2), (n) => n * 3)
    expect(isKnown(mapped) && mapped.value).toBe(6)
  })

  it('passes an absence through without invoking the mapper', () => {
    const mapper = vi.fn()
    const mapped = mapCertain(absent<number>('not-evaluated', 'why'), mapper)
    expect(mapper).not.toHaveBeenCalled()
    expect(isAbsent(mapped) && mapped.state).toBe('not-evaluated')
    expect(isAbsent(mapped) && mapped.detail).toBe('why')
  })

  it('drops a demo sample when the value type changes', () => {
    // A sample of one quantity is not a sample of another; showing `—` is
    // preferable to showing a number that illustrates something else.
    const carried = propagateAbsence<string, number>(
      demo('12ms') as { known: false; state: TruthState; detail?: string; sample?: string },
    )
    expect(isAbsent(carried) && carried.state).toBe('demo')
    expect(isAbsent(carried) && carried.sample).toBeUndefined()
  })
})

describe('certainText', () => {
  it('renders a known value, with an optional formatter', () => {
    expect(certainText(known(7))).toBe('7')
    expect(certainText(known(7), (n) => `${n} agents`)).toBe('7 agents')
  })

  it.each(TRUTH_STATES)('folds the %s state to the shared placeholder', (state) => {
    expect(certainText(absent<number>(state))).toBe(NO_DATA)
  })

  it('does not leak a demo sample into plain text', () => {
    // Text has nowhere to attach the "Demo data" label, so it shows nothing.
    expect(certainText(demo(1234))).toBe(NO_DATA)
  })
})
