/**
 * The Policy rail badge, on every outcome the shell can be in (AAASM-5369).
 *
 * The fold lives on the *shell*, so its failure mode is not a blank panel: a
 * throw here escapes the `ErrorBoundary` (which wraps `<Outlet />`, not the
 * chrome) and unmounts the whole application, on every route. The schema-invalid
 * cases below are therefore asserted for two separate properties — that nothing
 * throws, and that what comes back is an absence rather than a number.
 */
import { describe, expect, it } from 'vitest'
import { isAbsent, isKnown } from '../../../lib/truthfulness'
import { inactivePolicyBadgeFromQuery } from '../policyBadge'

const policy = (active: boolean) => ({
  name: 'baseline',
  version: 'v1',
  rule_count: 3,
  policy_yaml: 'metadata:\n  name: baseline\n',
  active,
})

describe('inactivePolicyBadgeFromQuery, on the bodies a healthy gateway sends', () => {
  it('counts the versions the list reports as not in force', () => {
    const badge = inactivePolicyBadgeFromQuery({
      data: [policy(false), policy(true), policy(false)],
      error: null,
    })
    expect(isKnown(badge) && badge.value).toBe(2)
  })

  it('reports a list with nothing inactive as the real zero it is', () => {
    // A populated, readable list that happens to have no inactive version is a
    // measurement. `suppressKnownZero` in the shell then hides the badge — which
    // is correct, and is why this case must stay `known`, not absent.
    const badge = inactivePolicyBadgeFromQuery({ data: [policy(true)], error: null })
    expect(isKnown(badge) && badge.value).toBe(0)
  })

  it('reports an empty list as zero, since an empty array is readable', () => {
    const badge = inactivePolicyBadgeFromQuery({ data: [], error: null })
    expect(isKnown(badge) && badge.value).toBe(0)
  })

  it('ignores fields it has never heard of', () => {
    const badge = inactivePolicyBadgeFromQuery({
      data: [{ ...policy(false), somethingNew: 'ignored' }],
      error: null,
    })
    expect(isKnown(badge) && badge.value).toBe(1)
  })
})

describe('inactivePolicyBadgeFromQuery, on a request that did not answer', () => {
  it('maps a failed request to unavailable, never to zero inactive policies', () => {
    const badge = inactivePolicyBadgeFromQuery({ isError: true, error: new Error('HTTP 503') })
    expect(isAbsent(badge) && badge.state).toBe('unavailable')
  })

  it('maps a request in flight to unknown, not to a fault', () => {
    const badge = inactivePolicyBadgeFromQuery({ isPending: true, error: null })
    expect(isAbsent(badge) && badge.state).toBe('unknown')
  })
})

/**
 * The AAASM-5369 cases: a `200` whose body is not a policy list.
 *
 * `usePoliciesQuery` throws on `!data?.items`, which is a truthiness check, not
 * an array check — so all of these reached the fold.
 */
describe('inactivePolicyBadgeFromQuery, on a schema-invalid success', () => {
  const UNREADABLE: readonly [string, unknown][] = [
    // The shape that threw: `.filter is not a function`.
    ['an object where the list should be', {}],
    ['a string where the list should be', 'none'],
    ['a scalar', 42],
    // The shape that fabricated: `!undefined` is `true`, so each unreadable row
    // counted itself as an inactive policy.
    ['rows with no `active` key', [{}, {}]],
    ['a row with a stringly-typed `active`', [policy(true), { active: 'true' }]],
  ]

  for (const [description, body] of UNREADABLE) {
    it(`reports ${description} as an absence, and does not throw`, () => {
      expect(() => inactivePolicyBadgeFromQuery({ data: body, error: null })).not.toThrow()
      const badge = inactivePolicyBadgeFromQuery({ data: body, error: null })
      expect(isKnown(badge)).toBe(false)
      if (!isKnown(badge)) {
        // Not `unavailable`: the request succeeded. The rail marks it unknown
        // and says why, rather than showing a number or vanishing.
        expect(badge.state).toBe('unknown')
        expect(badge.detail).toBeTruthy()
      }
    })
  }

  it('never returns the count the old fold fabricated from unreadable rows', () => {
    // Two rows with no `active` key used to count as two inactive policies.
    const badge = inactivePolicyBadgeFromQuery({ data: [{}, {}], error: null })
    expect(isKnown(badge) && badge.value === 2).toBe(false)
  })
})
