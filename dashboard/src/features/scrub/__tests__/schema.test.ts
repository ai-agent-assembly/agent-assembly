/**
 * What the scrub decoders accept, and what they refuse (AAASM-5366).
 *
 * The bodies below are the ones a real deployment produces — `{}` from a proxy
 * or a stubbed route, a row missing a field after a partial deploy, a scalar
 * where an array belongs — rather than adversarial nonsense. Each has to come
 * back as a *reason*, because a reason is what the page renders in place of the
 * figure it cannot state, and an unexplained `—` is only marginally better than
 * the white screen it replaces.
 */
import { describe, it, expect } from 'vitest'
import {
  decodeAgentEnforcement,
  decodePatternCounts,
  decodePosture,
  decodeScrubCatalogue,
  decodeScrubWindow,
} from '../schema'

const pattern = (kind: string) => ({
  kind,
  redaction_label: `[REDACTED:${kind}]`,
  category: 'api_key',
  severity: 'critical',
  builtin: true,
})

describe('decodeScrubCatalogue', () => {
  it('accepts the body the handler serves', () => {
    const result = decodeScrubCatalogue({ patterns: [pattern('AwsAccessKey')], total: 1 })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.patterns[0].kind).toBe('AwsAccessKey')
  })

  it('refuses a 200 with no patterns key, naming the field', () => {
    // The literal body the AAASM-5347 e2e harness served, and the one that
    // produced `Cannot read properties of undefined (reading 'length')`.
    const result = decodeScrubCatalogue({})
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('patterns')
      expect(result.reason).toContain('pattern catalogue')
    }
  })

  it('refuses a malformed pattern row, naming its position', () => {
    // A row is not a detail: `toCatalogue` reads five fields off every one of
    // them, so one bad row is as unreadable as a missing array.
    const result = decodeScrubCatalogue({
      patterns: [pattern('AwsAccessKey'), { kind: 'SsnPattern' }],
      total: 2,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('patterns.1')
  })

  it('lets a server add a field without blanking the page', () => {
    // Forward compatibility is the whole reason unknown keys are stripped
    // rather than rejected: a new field is not a reason to stop reporting the
    // ones that were already there.
    const result = decodeScrubCatalogue({
      patterns: [{ ...pattern('AwsAccessKey'), introduced_in: '0.2.0' }],
      total: 1,
      generated_at: '2026-08-01T00:00:00Z',
    })
    expect(result.ok).toBe(true)
  })

  it('states a cause an operator can act on, not just a fault', () => {
    const result = decodeScrubCatalogue({ patterns: 'all of them' })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toMatch(/proxy|deploy|version|newer or older/i)
  })
})

describe('decodeAgentEnforcement', () => {
  it('accepts the array the analytics route serves', () => {
    const result = decodeAgentEnforcement([{ agent_id: 'a1', blocked: 0, scrubbed: 3 }])
    expect(result.ok).toBe(true)
  })

  it('refuses an object where the route serves an array', () => {
    const result = decodeAgentEnforcement({})
    expect(result.ok).toBe(false)
  })

  it('refuses a row with no scrubbed count rather than summing undefined', () => {
    // `reduce` over such a row yields `NaN`, which renders as a value the page
    // was never told — an untruth with a number's authority.
    const result = decodeAgentEnforcement([{ agent_id: 'a1', blocked: 1 }])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('0.scrubbed')
  })
})

describe('decodePatternCounts', () => {
  it('accepts a populated tally', () => {
    const result = decodePatternCounts({
      counts: [{ kind: 'AwsAccessKey', hits: 2 }],
      total_hits: 2,
      window_seconds: 86_400,
    })
    expect(result.ok).toBe(true)
  })

  it('refuses a body with no counts key', () => {
    const result = decodePatternCounts({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('counts')
  })

  it('refuses a count row whose hits are not a number', () => {
    const result = decodePatternCounts({
      counts: [{ kind: 'AwsAccessKey', hits: 'lots' }],
      total_hits: 2,
      window_seconds: 86_400,
    })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('counts.0.hits')
  })
})

describe('decodePosture', () => {
  it('accepts the body the handler serves today, rate and all', () => {
    const result = decodePosture({
      leaks_intercepted: 11,
      distinct_kinds: 2,
      leak_rate: null,
      rate_computed: false,
      window_seconds: 2_592_000,
    })
    expect(result.ok).toBe(true)
  })

  it('accepts a body omitting the optional leak_rate entirely', () => {
    const result = decodePosture({
      leaks_intercepted: 11,
      distinct_kinds: 2,
      rate_computed: false,
      window_seconds: 2_592_000,
    })
    expect(result.ok).toBe(true)
  })

  it('refuses a body with no intercepted count', () => {
    // Without the guard this one does not throw — it renders `undefined` beside
    // "leaks intercepted", which is the same lie in quieter clothes.
    const result = decodePosture({ distinct_kinds: 0, rate_computed: false, window_seconds: 1 })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('leaks_intercepted')
  })
})

describe('decodeScrubWindow', () => {
  it('reads the window off either aggregation', () => {
    const result = decodeScrubWindow({ counts: [], total_hits: 0, window_seconds: 604_800 })
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.value.window_seconds).toBe(604_800)
  })

  it('asks for the window and nothing else', () => {
    // Deliberately narrow: a posture body with a malformed `leak_rate` must not
    // erase the window it did state. An absence has to be no wider than the
    // evidence for it.
    const result = decodeScrubWindow({ window_seconds: 86_400, leak_rate: 'unknowable' })
    expect(result.ok).toBe(true)
  })

  it('refuses a body that states no window', () => {
    const result = decodeScrubWindow({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toContain('window_seconds')
  })
})
