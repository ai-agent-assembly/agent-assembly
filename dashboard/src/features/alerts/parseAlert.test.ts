import { describe, expect, it } from 'vitest'
import { criticalFiringBadge, criticalFiringCount } from './alertBadge'
import { AlertShapeError, canonicalSeverity, canonicalStatus, normaliseAlert, parseAlertList } from './parseAlert'
import { known } from '../../lib/truthfulness'

/**
 * One row exactly as `aa-api` serialises it today.
 *
 * Transcribed from `AlertResponse` (aa-api/src/routes/alerts.rs:376-395) and
 * `StoredAlert` (aa-api/src/alerts/mod.rs:29-115): snake_case keys, lower-case
 * `severity` from the `AlertSeverity` `Display` impl, and a `status` drawn from
 * `"unresolved" | "resolved" | "suppressed"`. Deliberately *not* written in the
 * dashboard's vocabulary — a fixture that speaks the dashboard's own dialect
 * cannot detect the drift this module exists to close.
 */
function wireAlert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: '01JQ8Z9F2K3M4N5P6Q7R8S9T0V',
    severity: 'critical',
    category: 'budget',
    message: 'Budget threshold 90% crossed',
    timestamp: '2026-06-01T10:00:00Z',
    agent_id: 'support-agent',
    team_id: null,
    status: 'unresolved',
    updated_at: null,
    ...overrides,
  }
}

describe('canonicalStatus / canonicalSeverity — the live wire vocabulary', () => {
  it.each([
    ['unresolved', 'FIRING'],
    ['resolved', 'RESOLVED'],
    ['suppressed', 'SUPPRESSED'],
  ])('maps wire status %s onto %s', (wire, expected) => {
    expect(canonicalStatus(wire)).toBe(expected)
  })

  it.each([
    ['critical', 'CRITICAL'],
    ['warning', 'HIGH'],
    ['info', 'LOW'],
  ])('maps wire severity %s onto %s', (wire, expected) => {
    expect(canonicalSeverity(wire)).toBe(expected)
  })

  it('passes the dashboard vocabulary through unchanged', () => {
    // The rule-engine Stories (AAASM-1385…1389) are specified in the upper-case
    // form, so the boundary has to accept both without a flag day.
    expect(canonicalStatus('FIRING')).toBe('FIRING')
    expect(canonicalSeverity('CRITICAL')).toBe('CRITICAL')
  })

  it('throws rather than guessing at a vocabulary it does not know', () => {
    // Guessing is how a suppressed alert starts counting as firing.
    expect(() => canonicalStatus('acknowledged')).toThrow(AlertShapeError)
    expect(() => canonicalSeverity('catastrophic')).toThrow(AlertShapeError)
    expect(() => canonicalStatus(undefined)).toThrow(AlertShapeError)
    expect(() => canonicalSeverity(3)).toThrow(AlertShapeError)
  })

  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'])(
    'throws on the inherited object member %s instead of returning it',
    (inherited) => {
      // A plain-object lookup keyed by `WIRE_STATUS[value]` would resolve these
      // names to a truthy Object.prototype member and slip past the `if (mapped)`
      // guard — a payload we cannot read silently becoming a well-typed Alert.
      // That is the exact route by which "a suppressed alert starts counting as
      // firing". Keyed by a Map, `.get()` returns undefined for inherited names
      // and the documented fail-closed throw fires as designed.
      expect(() => canonicalStatus(inherited)).toThrow(AlertShapeError)
      expect(() => canonicalSeverity(inherited)).toThrow(AlertShapeError)
    },
  )
})

describe('normaliseAlert', () => {
  it('canonicalises a real wire row without inventing the fields it lacks', () => {
    const alert = normaliseAlert(wireAlert())

    expect(alert.severity).toBe('CRITICAL')
    expect(alert.status).toBe('FIRING')
    expect(alert.agentId).toBe('support-agent')
    // `timestamp` is capture time, which is when it first fired.
    expect(alert.firstFiredAt).toBe('2026-06-01T10:00:00Z')
    // The live AlertResponse carries no rule identity or destinations for a
    // budget alert. They resolve empty — never to something made up.
    expect(alert.ruleId).toBe('')
    expect(alert.ruleName).toBe('')
    expect(alert.destinationIds).toEqual([])
  })

  it('reads resolvedAt from updated_at only once the alert is actually resolved', () => {
    expect(
      normaliseAlert(wireAlert({ status: 'resolved', updated_at: '2026-06-01T11:00:00Z' }))
        .resolvedAt,
    ).toBe('2026-06-01T11:00:00Z')
    // An unresolved alert has a mutation timestamp too (e.g. a dedup bump); it
    // is not a resolution time and must not be reported as one.
    expect(
      normaliseAlert(wireAlert({ status: 'unresolved', updated_at: '2026-06-01T11:00:00Z' }))
        .resolvedAt,
    ).toBeNull()
  })

  it('accepts either spelling of the fields the wire and the dashboard share', () => {
    // The rule-engine Stories are specified in camelCase; the shipped budget
    // alerts are snake_case. Both have to survive the transition.
    const camel = normaliseAlert({
      id: 'a-1',
      severity: 'CRITICAL',
      status: 'FIRING',
      ruleId: 'r-9',
      ruleName: 'Budget > 90%',
      agentId: 'aa-001',
      firstFiredAt: '2026-06-01T09:00:00Z',
      destinationIds: ['slack-ops'],
    })
    expect(camel).toMatchObject({
      ruleId: 'r-9',
      ruleName: 'Budget > 90%',
      agentId: 'aa-001',
      firstFiredAt: '2026-06-01T09:00:00Z',
      destinationIds: ['slack-ops'],
    })

    const snake = normaliseAlert(
      wireAlert({ rule_id: 'r-9', rule_name: 'Budget > 90%', first_fired_at: '2026-06-01T09:00:00Z' }),
    )
    expect(snake).toMatchObject({
      ruleId: 'r-9',
      ruleName: 'Budget > 90%',
      firstFiredAt: '2026-06-01T09:00:00Z',
    })
  })

  it('falls back to an empty timestamp rather than inventing one', () => {
    // No `timestamp` and no camelCase spelling: the row genuinely does not say
    // when it fired, and guessing "now" would date an incident to page-load.
    expect(normaliseAlert(wireAlert({ timestamp: undefined })).firstFiredAt).toBe('')
  })

  it('ignores a destinations list that is not a list of strings', () => {
    expect(normaliseAlert(wireAlert({ destination_ids: [1, 2] })).destinationIds).toEqual([])
    expect(normaliseAlert(wireAlert({ destination_ids: 'slack-ops' })).destinationIds).toEqual([])
  })

  it('rejects a row it cannot identify', () => {
    expect(() => normaliseAlert(null)).toThrow(AlertShapeError)
    expect(() => normaliseAlert('nope')).toThrow(AlertShapeError)
    expect(() => normaliseAlert(wireAlert({ id: undefined }))).toThrow(AlertShapeError)
  })
})

describe('parseAlertList', () => {
  it('refuses to turn a malformed envelope into an empty fleet', () => {
    // The whole point: `items: []` here would be a confident claim that nothing
    // is wrong, derived from a payload we could not read.
    expect(() => parseAlertList(undefined)).toThrow(AlertShapeError)
    expect(() => parseAlertList(null)).toThrow(AlertShapeError)
    expect(() => parseAlertList({ nested: [] })).toThrow(AlertShapeError)
  })

  it('rejects the whole page when a single row is unreadable', () => {
    // Silently dropping the bad row would shrink the count with no signal —
    // the confident-zero failure in miniature.
    expect(() => parseAlertList([wireAlert(), wireAlert({ status: 'wat' })])).toThrow(
      AlertShapeError,
    )
  })
})

/**
 * The regression guard.
 *
 * This is the test that would have caught AAASM-5149's real defect. It drives
 * the *backend's* literal vocabulary through the parse and into the badge
 * selector the nav rail consumes, and asserts a firing CRITICAL is counted. If
 * anyone re-breaks the mapping — renames a wire value, drops the normalisation,
 * or reintroduces a blind cast — the badge silently returns to a permanent zero
 * and this goes red.
 */
describe('the nav badge counts real backend payloads (AAASM-5149 regression guard)', () => {
  it('counts a firing critical written in the wire vocabulary', () => {
    const page = parseAlertList([
      wireAlert({ id: 'a1', severity: 'critical', status: 'unresolved' }),
      wireAlert({ id: 'a2', severity: 'critical', status: 'resolved' }),
      wireAlert({ id: 'a3', severity: 'critical', status: 'suppressed' }),
      wireAlert({ id: 'a4', severity: 'warning', status: 'unresolved' }),
      wireAlert({ id: 'a5', severity: 'info', status: 'unresolved' }),
    ])

    // One row is both critical and still firing. Before the parse this was 0
    // for every possible live payload, and 0 renders no badge at all.
    expect(criticalFiringCount(page)).toBe(1)
    expect(criticalFiringBadge(known(page))).toEqual(known(1))
  })

  it('still reports a genuine wire-vocabulary quiet fleet as a known zero', () => {
    // A real zero must stay a real zero — the fix must not overcorrect into
    // "always show something".
    const page = parseAlertList([
      wireAlert({ id: 'a1', severity: 'warning', status: 'unresolved' }),
      wireAlert({ id: 'a2', severity: 'critical', status: 'resolved' }),
    ])
    expect(criticalFiringBadge(known(page))).toEqual(known(0))
  })
})
