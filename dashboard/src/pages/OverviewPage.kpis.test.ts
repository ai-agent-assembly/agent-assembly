import { describe, it, expect } from 'vitest'
import type { FleetAgent } from '../features/agents/fleetTypes'
import type { Alert } from '../features/alerts/types'
import { absent, isKnown, known, type AbsentValue, type Certain } from '../lib/truthfulness'
import {
  compareBySeverity,
  deriveOverviewKpis,
  meanScore,
  pickTopAlert,
  sumEnforcement,
} from './OverviewPage.kpis'
// Inlined at build time by Vite (`?raw`) so the no-hardcoded-score guard can
// read the module's own source without node fs access under jsdom.
import kpisSource from './OverviewPage.kpis.ts?raw'

function makeFleetAgent(overrides: Partial<FleetAgent> = {}): FleetAgent {
  return {
    source: {} as FleetAgent['source'],
    id: 'agent-1',
    name: 'research-bot',
    framework: 'langgraph',
    status: 'active',
    owner: null,
    mode: 'enforce',
    flagged: false,
    lastSeen: null,
    trust: null,
    blocked24h: null,
    scrubbed24h: null,
    note: null,
    ...overrides,
  }
}

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'alert-1',
    ruleId: 'rule-1',
    ruleName: 'shell.exec blocked',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'research-bot',
    firstFiredAt: '2026-01-01T14:02:08Z',
    resolvedAt: null,
    destinationIds: [],
    ...overrides,
  }
}

/** The enforcement lookup resolved successfully; its payload is irrelevant here. */
const ENFORCEMENT_OK: Certain<unknown> = known({})

/** Narrow to an absence, failing loudly if the value turned out to be known. */
function absence<T>(value: Certain<T>): AbsentValue<T> {
  if (isKnown(value)) {
    throw new Error(`expected an absence, got known value ${JSON.stringify(value.value)}`)
  }
  return value
}

/** Narrow to a known value, failing loudly if it turned out to be absent. */
function valueOf<T>(value: Certain<T>): T {
  if (!isKnown(value)) throw new Error(`expected a known value, got ${value.state}`)
  return value.value
}

describe('compareBySeverity', () => {
  it('orders CRITICAL before HIGH before MEDIUM before LOW', () => {
    const alerts = [
      makeAlert({ id: 'lo', severity: 'LOW' }),
      makeAlert({ id: 'med', severity: 'MEDIUM' }),
      makeAlert({ id: 'crit', severity: 'CRITICAL' }),
      makeAlert({ id: 'hi', severity: 'HIGH' }),
    ]
    const sorted = [...alerts].sort(compareBySeverity).map((a) => a.id)
    expect(sorted).toEqual(['crit', 'hi', 'med', 'lo'])
  })

  it('treats equal severities as equal (returns 0)', () => {
    expect(compareBySeverity(makeAlert({ severity: 'HIGH' }), makeAlert({ severity: 'HIGH' }))).toBe(
      0,
    )
  })
})

describe('pickTopAlert', () => {
  it('returns the most-severe alert', () => {
    const top = pickTopAlert([
      makeAlert({ id: 'med', severity: 'MEDIUM' }),
      makeAlert({ id: 'crit', severity: 'CRITICAL' }),
    ])
    expect(top?.id).toBe('crit')
  })

  it('returns undefined for an empty collection', () => {
    expect(pickTopAlert([])).toBeUndefined()
  })
})

describe('sumEnforcement', () => {
  const pick = (a: FleetAgent) => a.blocked24h

  it('totals the metric when every agent reported a count', () => {
    const total = sumEnforcement(
      [
        makeFleetAgent({ id: 'a', blocked24h: 3 }),
        makeFleetAgent({ id: 'b', blocked24h: 0 }),
        makeFleetAgent({ id: 'c', blocked24h: 2 }),
      ],
      pick,
      ENFORCEMENT_OK,
    )
    // A genuine zero contribution is a measurement and stays counted.
    expect(total).toEqual(known(5))
  })

  it('withholds the total when any agent did not report — never sums a null as zero', () => {
    const total = sumEnforcement(
      [
        makeFleetAgent({ id: 'a', blocked24h: 3 }),
        makeFleetAgent({ id: 'b', blocked24h: null }),
        makeFleetAgent({ id: 'c', blocked24h: 2 }),
      ],
      pick,
      ENFORCEMENT_OK,
    )
    expect(isKnown(total)).toBe(false)
    expect(absence(total).state).toBe('unknown')
    expect(absence(total).detail).toContain('1 of 3 agents')
  })

  it('propagates the enforcement query’s own absence rather than reporting zero', () => {
    const total = sumEnforcement(
      [makeFleetAgent({ id: 'a', blocked24h: null })],
      pick,
      absent('unavailable', 'HTTP 503'),
    )
    expect(absence(total).state).toBe('unavailable')
    expect(absence(total).detail).toBe('HTTP 503')
  })
})

describe('meanScore', () => {
  it('averages known scores and rounds', () => {
    expect(meanScore([known(97), known(88)])).toEqual(known(93))
  })

  it('is disqualified by any absent input rather than averaging the remainder', () => {
    const mean = meanScore([known(97), absent<number>('not-evaluated', 'no derivation')])
    expect(absence(mean).state).toBe('not-evaluated')
  })

  it('reports an absence when there is nothing to average', () => {
    expect(absence(meanScore([])).state).toBe('not-evaluated')
  })
})

describe('deriveOverviewKpis', () => {
  const someAlerts: Certain<readonly Alert[]> = known([])

  it('never reports a scrub posture score — the hardcoded 91 must not return', () => {
    // Vary everything the old constant ignored; the answer must stay an absence.
    for (const scrubbed of [null, 0, 226]) {
      const kpis = deriveOverviewKpis(
        [makeFleetAgent({ scrubbed24h: scrubbed })],
        someAlerts,
        ENFORCEMENT_OK,
      )
      expect(isKnown(kpis.scrubScore)).toBe(false)
      expect(absence(kpis.scrubScore).state).toBe('not-evaluated')
      expect(absence(kpis.scrubScore).detail).toContain('ADR 0026')
    }
  })

  it('excludes the scrub layer from the overall score instead of folding a constant in', () => {
    // 1 of 4 flagged: identity = 100 - 3 = 97; capability = round(100 - 25*0.5) = 88.
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', flagged: true }),
        makeFleetAgent({ id: 'b' }),
        makeFleetAgent({ id: 'c' }),
        makeFleetAgent({ id: 'd' }),
      ],
      someAlerts,
      ENFORCEMENT_OK,
    )
    expect(kpis.identityScore).toEqual(known(97))
    expect(kpis.capabilityScore).toEqual(known(88))
    // Mean of the two derived layers only — (97 + 88) / 2 = 93 (rounded).
    // The old expression averaged in scrubScore=91 and produced 92.
    expect(kpis.overallScore).toEqual(known(93))
  })

  it('withholds every posture score for an empty fleet rather than scoring it 100', () => {
    const kpis = deriveOverviewKpis([], someAlerts, ENFORCEMENT_OK)
    expect(kpis.total).toBe(0)
    expect(kpis.flagged).toBe(0)
    expect(absence(kpis.identityScore).state).toBe('not-evaluated')
    expect(absence(kpis.capabilityScore).state).toBe('not-evaluated')
    expect(absence(kpis.overallScore).state).toBe('not-evaluated')
  })

  it('counts modes and flags across the fleet', () => {
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', mode: 'enforce' }),
        makeFleetAgent({ id: 'b', mode: 'enforce' }),
        makeFleetAgent({ id: 'c', mode: 'shadow' }),
        makeFleetAgent({ id: 'd', mode: 'off' }),
        makeFleetAgent({ id: 'e', mode: 'enforce', flagged: true }),
      ],
      someAlerts,
      ENFORCEMENT_OK,
    )
    expect(kpis.total).toBe(5)
    expect(kpis.enforcing).toBe(3)
    expect(kpis.shadow).toBe(1)
    expect(kpis.flagged).toBe(1)
  })

  it('clamps the identity score at zero when many agents are flagged', () => {
    const fleet = Array.from({ length: 40 }, (_, i) =>
      makeFleetAgent({ id: `a${i}`, flagged: true }),
    )
    const kpis = deriveOverviewKpis(fleet, someAlerts, ENFORCEMENT_OK)
    expect(kpis.flagged).toBe(40)
    expect(kpis.identityScore).toEqual(known(0))
  })

  it('sums blocked and scrubbed when every agent reported', () => {
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', blocked24h: 3, scrubbed24h: 10 }),
        makeFleetAgent({ id: 'b', blocked24h: 2, scrubbed24h: 5 }),
      ],
      someAlerts,
      ENFORCEMENT_OK,
    )
    expect(kpis.blocked).toEqual(known(5))
    expect(kpis.scrubbed).toEqual(known(15))
  })

  it('withholds blocked and scrubbed when a metric is unreported (was `?? 0`)', () => {
    const kpis = deriveOverviewKpis(
      [
        makeFleetAgent({ id: 'a', blocked24h: 3, scrubbed24h: 10 }),
        makeFleetAgent({ id: 'b', blocked24h: null, scrubbed24h: null }),
      ],
      someAlerts,
      ENFORCEMENT_OK,
    )
    expect(isKnown(kpis.blocked)).toBe(false)
    expect(isKnown(kpis.scrubbed)).toBe(false)
  })

  it('keeps only FIRING alerts when the alerts query succeeded', () => {
    const kpis = deriveOverviewKpis(
      [makeFleetAgent()],
      known([
        makeAlert({ id: 'resolved-crit', severity: 'CRITICAL', status: 'RESOLVED' }),
        makeAlert({ id: 'firing-med', severity: 'MEDIUM', status: 'FIRING' }),
        makeAlert({ id: 'firing-crit', severity: 'CRITICAL', status: 'FIRING' }),
        makeAlert({ id: 'suppressed-hi', severity: 'HIGH', status: 'SUPPRESSED' }),
      ]),
      ENFORCEMENT_OK,
    )
    expect(valueOf(kpis.firingAlerts).map((a) => a.id)).toEqual(['firing-med', 'firing-crit'])
    expect(pickTopAlert(valueOf(kpis.firingAlerts))?.id).toBe('firing-crit')
  })

  it('reports an empty firing list as a real, known answer', () => {
    const kpis = deriveOverviewKpis(
      [makeFleetAgent()],
      known([makeAlert({ status: 'RESOLVED' })]),
      ENFORCEMENT_OK,
    )
    expect(valueOf(kpis.firingAlerts)).toEqual([])
  })

  it('propagates a failed alerts query instead of reporting zero firing alerts', () => {
    const kpis = deriveOverviewKpis(
      [makeFleetAgent()],
      absent<readonly Alert[]>('unavailable', 'HTTP 503'),
      ENFORCEMENT_OK,
    )
    expect(isKnown(kpis.firingAlerts)).toBe(false)
    expect(absence(kpis.firingAlerts).state).toBe('unavailable')
  })
})

/**
 * Comments are stripped before the source guards run: this module's own
 * docstrings quote the defect verbatim to explain it, and a guard that matched
 * prose would either fail on the explanation or force the explanation out.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
}

describe('OverviewPage.kpis source', () => {
  // AAASM-5113 regression guard. The defect was a mock placeholder promoted to
  // production, so the behavioural assertions above are backed by a source
  // check: reintroducing a literal posture score fails here even if it is wired
  // somewhere the unit tests do not reach.
  const code = stripComments(kpisSource)

  it('assigns no numeric literal to a posture score', () => {
    expect(code).not.toMatch(/(?:scrub|identity|capability|overall)Score\s*(?::[^=\n]*)?=\s*-?\d/i)
  })

  it('carries no bare 91 placeholder', () => {
    expect(code).not.toMatch(/=\s*91\b/)
  })

  it('strips comments before matching, so the guard reads code and not prose', () => {
    expect(stripComments('/* scrubScore = 91 */\nconst a = 1\n// scrubScore = 91')).toBe(
      '\nconst a = 1\n',
    )
  })
})
