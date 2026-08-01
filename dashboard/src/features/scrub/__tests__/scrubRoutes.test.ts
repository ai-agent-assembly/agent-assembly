/**
 * Branch coverage for the three AAASM-5174 routes the page now reads
 * (AAASM-5347).
 *
 * Each fold is asserted on all four outcomes the page can be in — in flight,
 * failed, answered-but-empty, answered-and-populated — because the failure this
 * lane exists to prevent is precisely a collapse of those branches into one
 * comfortable number. The empty branch gets the most attention: these routes
 * return a successful, all-zero body to a caller confined to no team, so reading
 * `0` as "nothing leaked" would put an unmeasured all-clear on the DLP surface.
 */
import { describe, it, expect } from 'vitest'
import * as scrubApi from '../api'
import {
  alertsForKind,
  formatWindow,
  leakRateFromQuery,
  patternAlertsFromQuery,
  scrubCatalogueFromQuery,
  scrubPostureFromQuery,
  scrubWindowFromQuery,
  type PatternCountsResponse,
  type PostureResponse,
  type ScrubCatalogueResponse,
} from '../api'
import { isKnown, type Certain, type QueryOutcome } from '../../../lib/truthfulness'

const pattern = (kind: string, severity = 'critical', category = 'api_key') => ({
  kind,
  redaction_label: `[REDACTED:${kind}]`,
  category,
  severity,
  builtin: true,
})

const catalogue = (...kinds: string[]): ScrubCatalogueResponse => ({
  patterns: kinds.map((k) => pattern(k)),
  total: kinds.length,
})

const counts = (
  rows: readonly { kind: string; hits: number }[],
  window_seconds = 86_400,
): PatternCountsResponse => ({
  counts: [...rows],
  total_hits: rows.reduce((s, r) => s + r.hits, 0),
  window_seconds,
})

const posture = (
  leaks_intercepted: number,
  distinct_kinds: number,
  extra: Partial<PostureResponse> = {},
): PostureResponse => ({
  leaks_intercepted,
  distinct_kinds,
  rate_computed: false,
  window_seconds: 2_592_000,
  ...extra,
})

describe('scrubCatalogueFromQuery', () => {
  it('returns the rows the gateway reports', () => {
    const value = scrubCatalogueFromQuery({ data: catalogue('AwsAccessKey', 'SsnPattern') })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value.map((p) => p.kind)).toEqual(['AwsAccessKey', 'SsnPattern'])
  })

  it('refuses to read an empty catalogue as "the gateway ships no detectors"', () => {
    // `CredentialKind::ALL` is a non-empty compile-time constant, so an empty
    // catalogue is a fault upstream of the response, not a measurement.
    const value = scrubCatalogueFromQuery({ data: catalogue() })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toMatch(/never empty/)
    }
  })

  it('maps a failed request to unavailable, never to an empty catalogue', () => {
    const value = scrubCatalogueFromQuery({ isError: true, error: new Error('HTTP 503') })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unavailable')
      expect(value.detail).toBe('HTTP 503')
    }
  })

  it('maps a request in flight to unknown, not to a fault', () => {
    const value = scrubCatalogueFromQuery({ isPending: true, error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unknown')
  })
})

describe('patternAlertsFromQuery', () => {
  it('keys the tally by credential kind and carries the server’s window', () => {
    const value = patternAlertsFromQuery({
      data: counts([{ kind: 'AwsAccessKey', hits: 2 }, { kind: 'OpenAiKey', hits: 1 }]),
    })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) {
      expect(value.value.byKind.get('AwsAccessKey')).toBe(2)
      expect(value.value.totalAlerts).toBe(3)
      expect(value.value.windowSeconds).toBe(86_400)
    }
  })

  it('refuses to read an empty tally as zero detections', () => {
    // The same 200 an admin gets on a genuinely idle window is what a caller
    // with neither admin nor a team scope gets on a busy one.
    const value = patternAlertsFromQuery({ data: counts([]) })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toMatch(/confined to no team/)
    }
  })

  it('maps a failed request to unavailable', () => {
    const value = patternAlertsFromQuery({ isError: true, error: new Error('HTTP 500') })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unavailable')
  })
})

describe('alertsForKind', () => {
  it('reports zero for a kind absent from a populated tally', () => {
    // A populated tally is itself evidence the read succeeded and the caller had
    // scope, and the handler emits a row only for kinds that fired — so a kind
    // it omits genuinely contributed no alert.
    const tally = patternAlertsFromQuery({ data: counts([{ kind: 'AwsAccessKey', hits: 2 }]) })
    const value = alertsForKind(tally, 'SsnPattern')
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(0)
  })

  it('propagates the tally’s absence rather than defaulting a row to zero', () => {
    const tally = patternAlertsFromQuery({ isError: true, error: new Error('boom') })
    const value = alertsForKind(tally, 'AwsAccessKey')
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unavailable')
  })
})

describe('scrubPostureFromQuery', () => {
  it('reports the intercepted-leak figures the window measured', () => {
    const value = scrubPostureFromQuery({ data: posture(4, 2) })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) {
      expect(value.value.leaksIntercepted).toBe(4)
      expect(value.value.distinctKinds).toBe(2)
      expect(value.value.windowSeconds).toBe(2_592_000)
    }
  })

  it('refuses to render a zero posture as a measured all-clear', () => {
    const value = scrubPostureFromQuery({ data: posture(0, 0) })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toMatch(/confined to no team/)
    }
  })

  it('maps a failed request to unavailable, never to a clean posture', () => {
    const value = scrubPostureFromQuery({ isError: true, error: new Error('HTTP 503') })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unavailable')
  })
})

describe('leakRateFromQuery', () => {
  it('is not-supported while the server reports no denominator', () => {
    const value = leakRateFromQuery({ data: posture(4, 2) })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('not-supported')
      expect(value.detail).toMatch(/denominator/)
    }
  })

  it('reports the rate the day the server computes one', () => {
    // Read off `rate_computed` rather than hard-coded, so the page starts
    // telling the truth by itself when the denominator lands.
    const value = leakRateFromQuery({ data: posture(4, 2, { rate_computed: true, leak_rate: 0.02 }) })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(0.02)
  })

  it('stays absent when the server claims a rate but sends none', () => {
    const value = leakRateFromQuery({ data: posture(4, 2, { rate_computed: true, leak_rate: null }) })
    expect(isKnown(value)).toBe(false)
  })
})

describe('scrubWindowFromQuery', () => {
  it('reports the window the server aggregated over, not the one requested', () => {
    const value = scrubWindowFromQuery({ data: counts([], 604_800) })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(604_800)
  })

  it('is absent when no body arrived, so no window can be stated', () => {
    const value = scrubWindowFromQuery({ isError: true, error: new Error('boom') })
    expect(isKnown(value)).toBe(false)
  })
})

/**
 * A schema-invalid `200` must degrade, and it must degrade *everywhere*
 * (AAASM-5366).
 *
 * The reported crash was one fold reading `patterns.length` off a body that had
 * no `patterns`. Fixing that fold alone would leave the identical hazard in the
 * three beside it, so this block does not name folds: it enumerates every
 * `*FromQuery` the module exports and puts the same unreadable bodies through
 * all of them. A fold added later without a decoder fails here without anyone
 * remembering to add a case for it.
 */
describe('every *FromQuery fold, against a body that does not match its schema', () => {
  type Fold = (outcome: QueryOutcome<unknown>) => Certain<unknown>
  const folds = Object.entries(scrubApi)
    .filter(([name, value]) => name.endsWith('FromQuery') && typeof value === 'function')
    .map(([name, value]): [string, Fold] => [name, value as Fold])
    // Code-unit order, not `localeCompare`: the expected list below is checked
    // literally, and a locale-sensitive sort would make it a different list on
    // a different machine.
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

  it('finds every fold the page uses, so the sweep cannot pass vacuously', () => {
    expect(folds.map(([name]) => name)).toEqual([
      'leakRateFromQuery',
      'patternAlertsFromQuery',
      'scrubCatalogueFromQuery',
      'scrubPostureFromQuery',
      'scrubWindowFromQuery',
      'scrubbed24hFromQuery',
    ])
  })

  // The bodies a proxy, a partial deploy and a stubbed test route actually
  // produce — `{}` is the one that was observed unmounting the page.
  //
  // `[]` is labelled for what it is rather than for what it does, because it
  // does two things: it is the wrong shape for five of the six folds, and for
  // `scrubbed24hFromQuery` — whose route really does serve an array — it is a
  // well-formed empty window. Both must end in an absence, which is the only
  // thing this sweep claims.
  const UNREADABLE: readonly [string, unknown][] = [
    ['an empty object', {}],
    ['a bare array', []],
    ['a scalar', 42],
    ['an envelope whose rows are empty objects', { patterns: [{}], counts: [{}], total: 1 }],
  ]

  for (const [name, fold] of folds) {
    for (const [description, body] of UNREADABLE) {
      it(`${name} reports an absence for ${description}, and does not throw`, () => {
        const value = fold({ data: body, error: null })
        expect(isKnown(value)).toBe(false)
        if (!isKnown(value)) {
          // Not `unavailable`: the request succeeded. The operator is told we
          // could not determine the value, and why.
          expect(value.state).toBe('unknown')
          expect(value.detail).toBeTruthy()
        }
      })
    }
  }
})

describe('scrubCatalogueFromQuery, on a schema-invalid success', () => {
  it('degrades to an absence naming the missing field rather than throwing', () => {
    const value = scrubCatalogueFromQuery({ data: {}, error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toContain('patterns')
    }
  })

  it('degrades on a malformed row too, since every row is read in full', () => {
    const value = scrubCatalogueFromQuery({
      data: { patterns: [pattern('AwsAccessKey'), { kind: 'SsnPattern' }], total: 2 },
      error: null,
    })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.detail).toContain('patterns.1')
  })

  it('does not fall back to an empty catalogue, which would read as "no detectors"', () => {
    const value = scrubCatalogueFromQuery({ data: {}, error: null })
    expect(value).not.toHaveProperty('value')
    if (!isKnown(value)) expect(value.detail).not.toMatch(/never empty/)
  })
})

describe('formatWindow', () => {
  it('renders whole-day and whole-hour windows in the units the API documents', () => {
    // 86 400s is the API's `24h` preset. `1d` would be equally true and read as
    // a different window from the `redactions / 24h` figure beside it, so
    // sub-two-day windows stay in hours.
    expect(formatWindow(86_400)).toBe('24h')
    expect(formatWindow(604_800)).toBe('7d')
    expect(formatWindow(2_592_000)).toBe('30d')
    expect(formatWindow(3_600)).toBe('1h')
    expect(formatWindow(90)).toBe('90s')
  })
})
